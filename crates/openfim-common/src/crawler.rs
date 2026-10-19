use std::path::Path;
use glob::Pattern;

use crate::error::{OpenFimError, Result};
use crate::hasher::StreamHasher;
use crate::metadata::FileMetadata;

/// Options for configuring the filesystem crawler
#[derive(Debug, Clone)]
pub struct CrawlOptions {
    /// Maximum directory recursion depth (default: 64)
    pub max_depth: usize,
    /// Follow directory symlinks (default: false to prevent symlink recursion loops)
    pub follow_symlinks: bool,
    /// Compiled glob patterns for ignored files/paths
    pub ignore_patterns: Vec<Pattern>,
}

impl Default for CrawlOptions {
    fn default() -> Self {
        Self {
            max_depth: 64,
            follow_symlinks: false,
            ignore_patterns: Vec::new(),
        }
    }
}

impl CrawlOptions {
    /// Adds ignore glob patterns (e.g. `*.tmp`, `**/cache/**`, `**/.git/**`)
    pub fn with_ignore_patterns<I, S>(mut self, patterns: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        for p in patterns {
            let pat = Pattern::new(p.as_ref()).map_err(|e| {
                OpenFimError::Other(format!("Invalid glob ignore pattern '{}': {}", p.as_ref(), e))
            })?;
            self.ignore_patterns.push(pat);
        }
        Ok(self)
    }

    /// Checks if a given path matches any configured ignore pattern
    pub fn is_ignored<P: AsRef<Path>>(&self, path: P) -> bool {
        let p_str = path.as_ref().to_string_lossy();
        for pattern in &self.ignore_patterns {
            if pattern.matches(&p_str) {
                return true;
            }
            // Also test matching just the filename component
            if let Some(file_name) = path.as_ref().file_name() {
                if pattern.matches(&file_name.to_string_lossy()) {
                    return true;
                }
            }
        }
        false
    }
}

/// Filesystem crawler that extracts metadata and cryptographic digests
pub struct FileCrawler {
    options: CrawlOptions,
}

impl FileCrawler {
    /// Creates a new FileCrawler with specified options
    pub fn new(options: CrawlOptions) -> Self {
        Self { options }
    }

    /// Recursively crawls the specified root path and extracts metadata for all matching entities
    pub fn crawl<P: AsRef<Path>>(
        &self,
        root: P,
        hasher: &mut StreamHasher,
    ) -> Result<Vec<FileMetadata>> {
        let root_path = root.as_ref().to_path_buf();
        let mut results = Vec::new();
        self.crawl_recursive(&root_path, 0, hasher, &mut results)?;
        Ok(results)
    }

    fn crawl_recursive(
        &self,
        current_path: &Path,
        current_depth: usize,
        hasher: &mut StreamHasher,
        results: &mut Vec<FileMetadata>,
    ) -> Result<()> {
        if self.options.is_ignored(current_path) {
            return Ok(());
        }

        if current_depth > self.options.max_depth {
            return Ok(());
        }

        // Extract metadata for the current node (using symlink_metadata)
        let meta = match FileMetadata::extract(current_path, hasher) {
            Ok(m) => m,
            Err(e) => {
                // If a transient read error occurs (e.g. permission denied on locked file), record error or skip
                return Err(e);
            }
        };

        let is_dir = meta.is_dir;
        let is_symlink = meta.is_symlink;

        results.push(meta);

        // If it's a directory (and not a symlink, unless follow_symlinks is true), walk children
        if is_dir && (!is_symlink || self.options.follow_symlinks) {
            let entries = match std::fs::read_dir(current_path) {
                Ok(rd) => rd,
                Err(e) => {
                    return Err(OpenFimError::IoError {
                        path: current_path.to_path_buf(),
                        source: e,
                    });
                }
            };

            for entry in entries {
                let entry = entry.map_err(|e| OpenFimError::IoError {
                    path: current_path.to_path_buf(),
                    source: e,
                })?;
                let child_path = entry.path();
                self.crawl_recursive(&child_path, current_depth + 1, hasher, results)?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{create_dir_all, File};
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn test_recursive_crawl_and_ignore() {
        let dir = tempdir().unwrap();
        let root = dir.path();

        // Create structure:
        // root/
        //   bin/
        //     app.exe
        //     temp.tmp
        //   etc/
        //     config.yaml
        let bin_dir = root.join("bin");
        let etc_dir = root.join("etc");
        create_dir_all(&bin_dir).unwrap();
        create_dir_all(&etc_dir).unwrap();

        let mut f1 = File::create(bin_dir.join("app.exe")).unwrap();
        f1.write_all(b"BINARY CONTENT").unwrap();

        let mut f2 = File::create(bin_dir.join("temp.tmp")).unwrap();
        f2.write_all(b"TEMP DATA").unwrap();

        let mut f3 = File::create(etc_dir.join("config.yaml")).unwrap();
        f3.write_all(b"key: value\n").unwrap();

        let options = CrawlOptions::default()
            .with_ignore_patterns(vec!["*.tmp"])
            .unwrap();

        let crawler = FileCrawler::new(options);
        let mut hasher = StreamHasher::default_sha256();
        let items = crawler.crawl(root, &mut hasher).unwrap();

        let paths: Vec<String> = items
            .iter()
            .map(|m| m.path.file_name().unwrap().to_string_lossy().to_string())
            .collect();

        assert!(paths.contains(&"app.exe".to_string()));
        assert!(paths.contains(&"config.yaml".to_string()));
        assert!(!paths.contains(&"temp.tmp".to_string()), "Ignored file temp.tmp was crawled!");
    }
}
