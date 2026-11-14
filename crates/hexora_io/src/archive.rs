use crate::{PythonFile, is_python_file};
use log::debug;
use std::fmt;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

// When a zip is password-protected, we try "infected" as the password.
// This is hardcoded for now, but works for testing purposes.
// The majority of malicious datasets are protected by this password.
// This is almost an industry standard in malware datasets.
const PASSWORD: &[u8] = b"infected";

/// Budgets that bound archive extraction. Shared by ZIP and TAR.GZ handling
/// so a small compressed package cannot exhaust scanner memory through
/// oversized entries or a huge total decompressed volume.
#[derive(Debug, Clone, Copy)]
pub struct ExtractionLimits {
    /// Maximum compressed size of the archive file itself, in bytes.
    pub max_archive_bytes: u64,
    /// Maximum number of entries allowed in an archive.
    pub max_entries: usize,
    /// Maximum decompressed size of a single extracted entry, in bytes.
    pub max_entry_bytes: u64,
    /// Maximum total decompressed bytes across all extracted entries.
    pub max_total_bytes: u64,
}

impl Default for ExtractionLimits {
    fn default() -> Self {
        Self {
            max_archive_bytes: 50 * 1024 * 1024,
            max_entries: 15000,
            max_entry_bytes: 10 * 1024 * 1024,
            max_total_bytes: 100 * 1024 * 1024,
        }
    }
}

/// Error returned when an archive cannot be extracted safely. Each variant
/// identifies the exact reason so callers can tell a budget violation or a
/// read failure apart from "no Python files found".
#[derive(Debug)]
pub enum ExtractionError {
    ArchiveTooLarge {
        path: PathBuf,
        size: u64,
        limit: u64,
    },
    TooManyEntries {
        path: PathBuf,
        limit: usize,
    },
    EntryTooLarge {
        path: PathBuf,
        entry: PathBuf,
        limit: u64,
    },
    TotalBytesExceeded {
        path: PathBuf,
        limit: u64,
    },
    Unreadable {
        path: PathBuf,
        reason: String,
    },
}

impl fmt::Display for ExtractionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExtractionError::ArchiveTooLarge { path, size, limit } => write!(
                f,
                "archive {:?} is {} bytes, exceeding the {} byte limit",
                path, size, limit
            ),
            ExtractionError::TooManyEntries { path, limit } => {
                write!(f, "archive {:?} has more than {} entries", path, limit)
            }
            ExtractionError::EntryTooLarge { path, entry, limit } => write!(
                f,
                "entry {:?} in archive {:?} exceeds the {} byte per-entry limit",
                entry, path, limit
            ),
            ExtractionError::TotalBytesExceeded { path, limit } => write!(
                f,
                "archive {:?} exceeds the {} byte total decompression limit",
                path, limit
            ),
            ExtractionError::Unreadable { path, reason } => {
                write!(f, "failed to read archive {:?}: {}", path, reason)
            }
        }
    }
}

impl std::error::Error for ExtractionError {}

fn unreadable(path: &Path, reason: impl fmt::Display) -> ExtractionError {
    ExtractionError::Unreadable {
        path: path.to_owned(),
        reason: reason.to_string(),
    }
}

/// Read a single archive entry into a string, enforcing the per-entry and
/// total decompression budgets. Returns `Ok(None)` for entries that are not
/// valid UTF-8; those are skipped rather than aborting the archive.
fn read_python_entry(
    reader: &mut impl Read,
    archive_path: &Path,
    entry_path: &Path,
    limits: &ExtractionLimits,
    total_bytes: &mut u64,
) -> Result<Option<String>, ExtractionError> {
    let mut bytes = Vec::new();
    reader
        .take(limits.max_entry_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| unreadable(archive_path, e))?;

    if bytes.len() as u64 > limits.max_entry_bytes {
        return Err(ExtractionError::EntryTooLarge {
            path: archive_path.to_owned(),
            entry: entry_path.to_owned(),
            limit: limits.max_entry_bytes,
        });
    }

    *total_bytes += bytes.len() as u64;
    if *total_bytes > limits.max_total_bytes {
        return Err(ExtractionError::TotalBytesExceeded {
            path: archive_path.to_owned(),
            limit: limits.max_total_bytes,
        });
    }

    match String::from_utf8(bytes) {
        Ok(content) => Ok(Some(content)),
        Err(_) => {
            debug!(
                "Skipping non-UTF-8 entry {:?} in {:?}",
                entry_path, archive_path
            );
            Ok(None)
        }
    }
}

pub struct TarGzIterator {
    archive_path: PathBuf,
    matched_count: usize,
    files: std::vec::IntoIter<PythonFile>,
}

impl TarGzIterator {
    pub fn new(path: &Path, limits: &ExtractionLimits) -> Result<Self, ExtractionError> {
        let metadata = fs::metadata(path).map_err(|e| unreadable(path, e))?;

        if metadata.len() > limits.max_archive_bytes {
            return Err(ExtractionError::ArchiveTooLarge {
                path: path.to_owned(),
                size: metadata.len(),
                limit: limits.max_archive_bytes,
            });
        }

        let file = fs::File::open(path).map_err(|e| unreadable(path, e))?;
        let tar_gz = flate2::read::GzDecoder::new(file);
        let mut archive = tar::Archive::new(tar_gz);

        let mut python_files = Vec::new();
        let entries = archive.entries().map_err(|e| unreadable(path, e))?;

        let mut total_bytes = 0u64;
        let mut count = 0;
        for entry in entries {
            count += 1;
            if count > limits.max_entries {
                return Err(ExtractionError::TooManyEntries {
                    path: path.to_owned(),
                    limit: limits.max_entries,
                });
            }

            let mut entry = entry.map_err(|e| unreadable(path, e))?;
            let path_in_tar = match entry.path().ok() {
                Some(p) => p.to_path_buf(),
                None => {
                    debug!("Skipping entry with invalid path in {:?}", path);
                    continue;
                }
            };

            if is_python_file(&path_in_tar) {
                if let Some(content) =
                    read_python_entry(&mut entry, path, &path_in_tar, limits, &mut total_bytes)?
                {
                    python_files.push(PythonFile {
                        file_path: path_in_tar,
                        content,
                        archive_path: Some(path.to_owned()),
                    });
                }
            }
        }

        Ok(TarGzIterator {
            archive_path: path.to_owned(),
            matched_count: 0,
            files: python_files.into_iter(),
        })
    }
}

impl Iterator for TarGzIterator {
    type Item = PythonFile;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(file) = self.files.next() {
            self.matched_count += 1;
            return Some(file);
        }

        if self.matched_count == 0 {
            debug!("No Python files in tar.gz: {:?}", self.archive_path);
            self.matched_count = 1;
        }

        None
    }
}

pub struct ZipIterator {
    archive_path: PathBuf,
    matched_count: usize,
    files: std::vec::IntoIter<PythonFile>,
}

impl ZipIterator {
    pub fn new(path: &Path, limits: &ExtractionLimits) -> Result<Self, ExtractionError> {
        let metadata = fs::metadata(path).map_err(|e| unreadable(path, e))?;

        if metadata.len() > limits.max_archive_bytes {
            return Err(ExtractionError::ArchiveTooLarge {
                path: path.to_owned(),
                size: metadata.len(),
                limit: limits.max_archive_bytes,
            });
        }

        let file = fs::File::open(path).map_err(|e| unreadable(path, e))?;
        let mut archive = zip::ZipArchive::new(file).map_err(|e| unreadable(path, e))?;
        let num_files = archive.len();

        if num_files > limits.max_entries {
            return Err(ExtractionError::TooManyEntries {
                path: path.to_owned(),
                limit: limits.max_entries,
            });
        }

        let mut python_files = Vec::new();
        let mut total_bytes = 0u64;
        for i in 0..num_files {
            let mut file = match archive.by_index_decrypt(i, PASSWORD) {
                Ok(f) => f,
                Err(_) => continue,
            };

            if !file.is_file() {
                continue;
            }

            let path_in_zip = PathBuf::from(file.name());

            if is_python_file(&path_in_zip) {
                if file.size() > limits.max_entry_bytes {
                    return Err(ExtractionError::EntryTooLarge {
                        path: path.to_owned(),
                        entry: path_in_zip,
                        limit: limits.max_entry_bytes,
                    });
                }

                if let Some(content) =
                    read_python_entry(&mut file, path, &path_in_zip, limits, &mut total_bytes)?
                {
                    python_files.push(PythonFile {
                        file_path: path_in_zip,
                        content,
                        archive_path: Some(path.to_owned()),
                    });
                }
            }
        }

        Ok(ZipIterator {
            archive_path: path.to_owned(),
            matched_count: 0,
            files: python_files.into_iter(),
        })
    }
}

impl Iterator for ZipIterator {
    type Item = PythonFile;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(file) = self.files.next() {
            self.matched_count += 1;
            return Some(file);
        }

        if self.matched_count == 0 {
            debug!("No Python files in zip: {:?}", self.archive_path);
            self.matched_count = 1;
        }

        None
    }
}
