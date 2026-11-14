mod archive;
pub mod base64;
pub mod encoding;
pub mod escape;
pub mod hex;
pub mod locator;
pub mod macros;
pub mod telegram;

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex};

use archive::{TarGzIterator, ZipIterator};
use rayon::prelude::*;

pub use archive::{ExtractionError, ExtractionLimits};

/// Maximum number of archives decompressed in parallel. Bounds the transient
/// peak: only this many tar.gz/zip files are fully expanded into memory at once.
const MAX_CONCURRENT_EXTRACTIONS: usize = 4;

/// Number of files that may be buffered in the extraction stream's channel.
const MAX_QUEUED_FILES: usize = 64;

/// A counting semaphore backed by a mutex + condvar (std's is unstable).
#[derive(Debug)]
struct Semaphore {
    count: Mutex<usize>,
    condvar: Condvar,
}

impl Semaphore {
    fn new(permits: usize) -> Self {
        Self {
            count: Mutex::new(permits),
            condvar: Condvar::new(),
        }
    }

    fn acquire(&self) -> SemaphorePermit<'_> {
        let mut count = self.count.lock().unwrap();
        while *count == 0 {
            count = self.condvar.wait(count).unwrap();
        }
        *count -= 1;
        SemaphorePermit { semaphore: self }
    }
}

pub struct SemaphorePermit<'a> {
    semaphore: &'a Semaphore,
}

impl Drop for SemaphorePermit<'_> {
    fn drop(&mut self) {
        let mut count = self.semaphore.count.lock().unwrap();
        *count += 1;
        self.semaphore.condvar.notify_one();
    }
}

fn has_extension(path: &Path, ext: &str) -> bool {
    path.extension()
        .is_some_and(|e| e.eq_ignore_ascii_case(ext))
}

pub(crate) fn is_python_file(path: &Path) -> bool {
    has_extension(path, "py")
}

fn is_zip_file(path: &Path) -> bool {
    has_extension(path, "zip")
}

fn is_tar_gz_file(path: &Path) -> bool {
    let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    filename.to_lowercase().ends_with(".tar.gz")
}

pub enum EntryIterator {
    FileSystem(std::iter::Once<PythonFile>),
    Zip(ZipIterator),
    TarGz(TarGzIterator),
    Empty,
}

impl Iterator for EntryIterator {
    type Item = PythonFile;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            EntryIterator::FileSystem(it) => it.next(),
            EntryIterator::Zip(it) => it.next(),
            EntryIterator::TarGz(it) => it.next(),
            EntryIterator::Empty => None,
        }
    }
}

pub struct PythonFile {
    pub file_path: PathBuf,
    pub content: String,
    pub archive_path: Option<PathBuf>,
}

impl PythonFile {
    pub fn full_path(&self) -> String {
        match &self.archive_path {
            Some(zp) => format!("{}:{}", zp.display(), self.file_path.display()),
            None => self.file_path.display().to_string(),
        }
    }
}

pub fn read_exclude_names(path: &Path) -> Result<HashSet<String>, std::io::Error> {
    let content = fs::read_to_string(path)?;
    Ok(content
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect())
}

/// A stream of Python files produced in discovery order by a background
/// extraction thread. Memory is bounded: only `MAX_QUEUED_FILES` files sit in
/// the channel at a time, and the extraction thread blocks when it fills up.
///
/// Items are `Result`s: an archive that violates the extraction budgets or
/// cannot be read yields one `Err` and stops the stream, so partial archive
/// content is never passed downstream on its own.
pub struct PythonFileStream {
    rx: std::sync::mpsc::Receiver<Result<PythonFile, ExtractionError>>,
}

impl Iterator for PythonFileStream {
    type Item = Result<PythonFile, ExtractionError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.rx.recv().ok()
    }
}

fn is_excluded(name: Option<&std::ffi::OsStr>, exclude_names: &HashSet<String>) -> bool {
    name.and_then(|n| n.to_str())
        .is_some_and(|n| exclude_names.contains(n))
}

/// Discover Python files (including inside archives) and stream them in order.
///
/// The walk happens synchronously so callers can report "no Python files"
/// errors up front; extraction runs on a single background thread that pushes
/// files through a bounded channel, so decompression overlaps with auditing.
pub fn spawn_python_files(
    path: &Path,
    exclude_names: Option<&HashSet<String>>,
) -> Result<PythonFileStream, String> {
    spawn_python_files_with_limits(path, exclude_names, ExtractionLimits::default())
}

/// Like [`spawn_python_files`], but with caller-provided extraction budgets.
pub fn spawn_python_files_with_limits(
    path: &Path,
    exclude_names: Option<&HashSet<String>>,
    limits: ExtractionLimits,
) -> Result<PythonFileStream, String> {
    let exclude_names = exclude_names.cloned().unwrap_or_default();

    let entries: Vec<_> = walkdir::WalkDir::new(path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .collect();

    let relevant: Vec<_> = entries
        .into_iter()
        .filter(|e| {
            let path = e.path();
            !is_excluded(path.file_name(), &exclude_names)
                && (is_python_file(path) || is_zip_file(path) || is_tar_gz_file(path))
        })
        .collect();

    if relevant.is_empty() {
        return Err("No Python files found".to_string());
    }

    let (tx, rx) = std::sync::mpsc::sync_channel(MAX_QUEUED_FILES);

    std::thread::Builder::new()
        .name("hexora-extract".to_string())
        .spawn(move || {
            for entry in relevant {
                match extract_from_entry(&entry, &exclude_names, &limits) {
                    Ok(files) => {
                        for file in files {
                            if tx.send(Ok(file)).is_err() {
                                return;
                            }
                        }
                    }
                    Err(e) => {
                        // Stop immediately: a budget violation or unreadable
                        // archive aborts extraction with an identifiable error.
                        let _ = tx.send(Err(e));
                        return;
                    }
                }
            }
        })
        .map_err(|e| e.to_string())?;

    Ok(PythonFileStream { rx })
}

/// List all Python files in the given path, including those inside .zip and .tar.gz archives.
pub fn list_python_files(
    path: &Path,
    exclude_names: Option<&HashSet<String>>,
) -> Result<impl Iterator<Item = PythonFile>, ExtractionError> {
    list_python_files_with_limits(path, exclude_names, ExtractionLimits::default())
}

/// Like [`list_python_files`], but with caller-provided extraction budgets.
///
/// Returns an error as soon as any archive violates the budgets or cannot be
/// read; no partially extracted content is yielded.
pub fn list_python_files_with_limits(
    path: &Path,
    exclude_names: Option<&HashSet<String>>,
    limits: ExtractionLimits,
) -> Result<impl Iterator<Item = PythonFile>, ExtractionError> {
    let exclude_names = exclude_names.cloned().unwrap_or_default();
    let entries: Vec<_> = walkdir::WalkDir::new(path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .collect();

    // Extract file contents and decompress archives in parallel. Each
    // filesystem entry is an independent unit of work; ordering is preserved.
    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_EXTRACTIONS));
    let files: Vec<EntryIterator> = entries
        .into_par_iter()
        .map(move |entry| {
            let _permit = semaphore.acquire();
            extract_from_entry(&entry, &exclude_names, &limits)
        })
        .collect::<Result<_, _>>()?;

    Ok(files.into_iter().flatten())
}

fn extract_from_entry(
    entry: &walkdir::DirEntry,
    exclude_names: &HashSet<String>,
    limits: &ExtractionLimits,
) -> Result<EntryIterator, ExtractionError> {
    let path = entry.path();

    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        if exclude_names.contains(name) {
            return Ok(EntryIterator::Empty);
        }
    }

    if is_python_file(path) {
        if let Ok(content) = fs::read_to_string(path) {
            return Ok(EntryIterator::FileSystem(std::iter::once(PythonFile {
                file_path: path.to_owned(),
                content,
                archive_path: None,
            })));
        }
    }

    if is_zip_file(path) {
        return ZipIterator::new(path, limits).map(EntryIterator::Zip);
    }

    if is_tar_gz_file(path) {
        return TarGzIterator::new(path, limits).map(EntryIterator::TarGz);
    }

    Ok(EntryIterator::Empty)
}

pub fn dump_package(path: &Path, filter: Option<&str>) -> Result<(), std::io::Error> {
    let path_filename = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown");
    println!("#=== Dumping package: {} ===", path_filename);
    for file in list_python_files(path, None).map_err(std::io::Error::other)? {
        if file.archive_path.is_some() {
            if let Some(f) = filter {
                if !file.file_path.to_string_lossy().contains(f) {
                    continue;
                }
            }
            println!("#--- File: {:?} ---", file.file_path);
            println!("{}", file.content);
            println!("#-----------------------");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{
        ExtractionError, ExtractionLimits, list_python_files, list_python_files_with_limits,
        spawn_python_files_with_limits,
    };
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::collections::HashSet;
    use std::fs;
    use std::io::Write;
    use std::path::Path;
    use tempfile::tempdir;
    use zip::write::SimpleFileOptions;

    fn write_zip(dir: &Path, name: &str, entries: &[(&str, &[u8])]) {
        let file = fs::File::create(dir.join(name)).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = SimpleFileOptions::default();
        for (entry_name, content) in entries {
            zip.start_file(entry_name, options).unwrap();
            zip.write_all(content).unwrap();
        }
        zip.finish().unwrap();
    }

    fn write_tar_gz(dir: &Path, name: &str, entries: &[(&str, &[u8])]) {
        let file = fs::File::create(dir.join(name)).unwrap();
        let enc = GzEncoder::new(file, Compression::default());
        let mut tar = tar::Builder::new(enc);
        for (entry_name, content) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_cksum();
            tar.append_data(&mut header, entry_name, &content[..])
                .unwrap();
        }
        tar.finish().unwrap();
    }

    fn tight_limits() -> ExtractionLimits {
        ExtractionLimits {
            max_entry_bytes: 16,
            max_total_bytes: 64,
            ..ExtractionLimits::default()
        }
    }

    #[test]
    fn test_list_python_files() {
        let dir = tempdir().unwrap();

        let py_path = dir.path().join("test.py");
        fs::write(&py_path, "print('hello')").unwrap();

        let archive_path = dir.path().join("test.zip");
        let file = fs::File::create(&archive_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = SimpleFileOptions::default();

        zip.start_file("inner.py", options).unwrap();
        zip.write_all(b"print('zip')").unwrap();
        zip.finish().unwrap();

        let txt_path = dir.path().join("test.txt");
        fs::write(&txt_path, "ignore me").unwrap();

        let results: Vec<_> = list_python_files(dir.path(), None).unwrap().collect();

        assert_eq!(results.len(), 2);

        let mut found_py = false;
        let mut found_zip_py = false;

        for file in results {
            if file.file_path.ends_with("test.py") {
                assert_eq!(file.content, "print('hello')");
                assert!(file.archive_path.is_none());
                assert_eq!(file.full_path(), py_path.display().to_string());
                found_py = true;
            } else if file.file_path.ends_with("inner.py") && file.archive_path.is_some() {
                assert_eq!(file.content, "print('zip')");
                assert!(file.archive_path.as_ref().unwrap().ends_with("test.zip"));
                assert_eq!(
                    file.full_path(),
                    format!("{}:inner.py", archive_path.display())
                );
                found_zip_py = true;
            }
        }

        assert!(found_py);
        assert!(found_zip_py);
    }

    #[test]
    fn test_list_python_files_with_exclude() {
        let dir = tempdir().unwrap();

        let py_path1 = dir.path().join("test1.py");
        fs::write(&py_path1, "print('hello 1')").unwrap();

        let py_path2 = dir.path().join("test2.py");
        fs::write(&py_path2, "print('hello 2')").unwrap();

        let archive_path = dir.path().join("test.zip");
        let file = fs::File::create(&archive_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = SimpleFileOptions::default();
        zip.start_file("inner.py", options).unwrap();
        zip.write_all(b"print('zip')").unwrap();
        zip.finish().unwrap();

        let mut exclude = HashSet::new();
        exclude.insert("test1.py".to_string());
        exclude.insert("test.zip".to_string());

        let results: Vec<_> = list_python_files(dir.path(), Some(&exclude))
            .unwrap()
            .collect();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].file_path.file_name().unwrap(), "test2.py");
    }

    #[test]
    fn test_list_python_files_tar_gz() {
        let dir = tempdir().unwrap();

        let tar_gz_path = dir.path().join("test.tar.gz");
        {
            let file = fs::File::create(&tar_gz_path).unwrap();
            let enc = GzEncoder::new(file, Compression::default());
            let mut tar = tar::Builder::new(enc);

            let mut header = tar::Header::new_gnu();
            let content = b"print('tar.gz')";
            header.set_size(content.len() as u64);
            header.set_cksum();
            tar.append_data(&mut header, "inner.py", &content[..])
                .unwrap();
            tar.finish().unwrap();
        }

        let results: Vec<_> = list_python_files(dir.path(), None).unwrap().collect();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].content, "print('tar.gz')");
        assert!(
            results[0]
                .archive_path
                .as_ref()
                .unwrap()
                .ends_with("test.tar.gz")
        );
        assert_eq!(results[0].file_path, std::path::Path::new("inner.py"));
    }

    #[test]
    fn test_no_python_files_in_zip() {
        let dir = tempdir().unwrap();

        let archive_path = dir.path().join("empty.zip");
        let file = fs::File::create(&archive_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = SimpleFileOptions::default();

        zip.start_file("test.txt", options).unwrap();
        zip.write_all(b"not a python file").unwrap();
        zip.finish().unwrap();

        let results: Vec<_> = list_python_files(dir.path(), None).unwrap().collect();
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn test_password_protected_zip() {
        let dir = tempdir().unwrap();
        let archive_path = dir.path().join("protected.zip");
        let file = fs::File::create(&archive_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);

        let options =
            SimpleFileOptions::default().with_aes_encryption(zip::AesMode::Aes256, "infected");

        zip.start_file("secret.py", options).unwrap();
        zip.write_all(b"print('infected')").unwrap();
        zip.finish().unwrap();

        let results: Vec<_> = list_python_files(dir.path(), None).unwrap().collect();

        assert_eq!(
            results.len(),
            1,
            "Should have found one python file in protected zip"
        );
        assert!(results[0].file_path.ends_with("secret.py"));
        assert!(
            results[0]
                .archive_path
                .as_ref()
                .unwrap()
                .ends_with("protected.zip")
        );
        assert_eq!(results[0].content, "print('infected')");
    }

    #[test]
    fn test_read_exclude_names() {
        let dir = tempdir().unwrap();
        let exclude_path = dir.path().join("exclude.txt");
        fs::write(
            &exclude_path,
            "file1.py\n  file2.py  \n\n# comment\n  # another comment\nfile3.py",
        )
        .unwrap();

        let exclude = crate::read_exclude_names(&exclude_path).unwrap();
        assert_eq!(exclude.len(), 3);
        assert!(exclude.contains("file1.py"));
        assert!(exclude.contains("file2.py"));
        assert!(exclude.contains("file3.py"));
        assert!(!exclude.contains("# comment"));
    }

    #[test]
    fn test_zip_entry_size_limit() {
        let dir = tempdir().unwrap();
        write_zip(
            dir.path(),
            "big.zip",
            &[("big.py", b"print('this file is way too large')")],
        );

        let err = list_python_files_with_limits(dir.path(), None, tight_limits())
            .err()
            .unwrap();
        assert!(
            matches!(err, ExtractionError::EntryTooLarge { ref entry, .. } if entry.ends_with("big.py")),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_zip_total_bytes_limit() {
        let dir = tempdir().unwrap();
        write_zip(
            dir.path(),
            "many.zip",
            &[
                ("a.py", b"print('aaaa')"),
                ("b.py", b"print('bbbb')"),
                ("c.py", b"print('cccc')"),
                ("d.py", b"print('dddd')"),
                ("e.py", b"print('eeee')"),
            ],
        );

        let err = list_python_files_with_limits(dir.path(), None, tight_limits())
            .err()
            .unwrap();
        assert!(
            matches!(err, ExtractionError::TotalBytesExceeded { .. }),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_tar_gz_entry_size_limit() {
        let dir = tempdir().unwrap();
        write_tar_gz(
            dir.path(),
            "big.tar.gz",
            &[("big.py", b"print('this file is way too large')")],
        );

        let err = list_python_files_with_limits(dir.path(), None, tight_limits())
            .err()
            .unwrap();
        assert!(
            matches!(err, ExtractionError::EntryTooLarge { ref entry, .. } if entry.ends_with("big.py")),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_tar_gz_total_bytes_limit() {
        let dir = tempdir().unwrap();
        write_tar_gz(
            dir.path(),
            "many.tar.gz",
            &[
                ("a.py", b"print('aaaa')"),
                ("b.py", b"print('bbbb')"),
                ("c.py", b"print('cccc')"),
                ("d.py", b"print('dddd')"),
                ("e.py", b"print('eeee')"),
            ],
        );

        let err = list_python_files_with_limits(dir.path(), None, tight_limits())
            .err()
            .unwrap();
        assert!(
            matches!(err, ExtractionError::TotalBytesExceeded { .. }),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_small_archives_within_limits() {
        let dir = tempdir().unwrap();
        write_zip(dir.path(), "ok.zip", &[("inner.py", b"print('zip')")]);
        write_tar_gz(dir.path(), "ok.tar.gz", &[("inner.py", b"print('tar')")]);

        let results: Vec<_> = list_python_files_with_limits(dir.path(), None, tight_limits())
            .unwrap()
            .collect();

        assert_eq!(results.len(), 2);
        assert!(
            results
                .iter()
                .any(|f| f.content == "print('zip')" && f.archive_path.is_some())
        );
        assert!(
            results
                .iter()
                .any(|f| f.content == "print('tar')" && f.archive_path.is_some())
        );
    }

    #[test]
    fn test_encrypted_zip_within_limits() {
        let dir = tempdir().unwrap();
        let archive_path = dir.path().join("protected.zip");
        let file = fs::File::create(&archive_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options =
            SimpleFileOptions::default().with_aes_encryption(zip::AesMode::Aes256, "infected");
        zip.start_file("secret.py", options).unwrap();
        zip.write_all(b"print('infected')").unwrap();
        zip.finish().unwrap();

        let limits = ExtractionLimits {
            max_entry_bytes: 64,
            max_total_bytes: 256,
            ..ExtractionLimits::default()
        };
        let results: Vec<_> = list_python_files_with_limits(dir.path(), None, limits)
            .unwrap()
            .collect();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].content, "print('infected')");
    }

    #[test]
    fn test_stream_reports_extraction_error() {
        let dir = tempdir().unwrap();
        write_zip(
            dir.path(),
            "big.zip",
            &[("big.py", b"print('this file is way too large')")],
        );

        let stream = spawn_python_files_with_limits(dir.path(), None, tight_limits()).unwrap();
        let items: Vec<_> = stream.collect();

        assert_eq!(items.len(), 1, "stream must stop after the error");
        assert!(
            matches!(&items[0], Err(ExtractionError::EntryTooLarge { .. })),
            "unexpected item: {:?}",
            items[0].as_ref().map(|f| f.full_path())
        );
    }

    #[test]
    fn test_unreadable_zip_is_identifiable() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("broken.zip"), b"not a real zip archive").unwrap();

        let err = list_python_files(dir.path(), None).err().unwrap();
        assert!(
            matches!(err, ExtractionError::Unreadable { .. }),
            "unexpected error: {err}"
        );
    }
}
