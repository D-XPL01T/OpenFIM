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
    /// Skip unreadable / permission denied files instead of aborting the crawl
    pub skip_inaccessible: bool,
    /// Compiled glob patterns for ignored files/paths
    pub ignore_patterns: Vec<Pattern>,
}

impl Default for CrawlOptions {
    fn default() -> Self {
        Self {
            max_depth: 64,
            follow_symlinks: false,
            // Default to skipping unreadable entries. A baseline sweep of a real
            // system root will always encounter at least one file the agent cannot
            // open (sockets, /proc entries, root-only secrets, files locked by
            // another process on Windows). Aborting the whole crawl on the first
            // such entry would leave the operator with no baseline at all, which is
            // strictly worse than a baseline with a recorded gap.
            skip_inaccessible: true,
            ignore_patterns: Vec::new(),
        }
    }
}

/// Normalizes a path for glob matching: forward slashes everywhere, and lowercase on
/// platforms with case-insensitive filesystems.
///
/// Without separator normalization a pattern such as `**/cache/**` can never match a
/// Windows path like `C:\app\cache\x`, because `glob::Pattern` only ever treats `/`
/// as a separator. That silently disables every configured exclusion on Windows.
pub(crate) fn normalize_for_match(path: &Path) -> String {
    let s = path.to_string_lossy().replace('\\', "/");
    if cfg!(windows) {
        s.to_lowercase()
    } else {
        s
    }
}

/// Normalizes a user-supplied glob pattern the same way as the paths it is tested against.
pub(crate) fn normalize_pattern(pattern: &str) -> String {
    let s = pattern.replace('\\', "/");
    if cfg!(windows) {
        s.to_lowercase()
    } else {
        s
    }
}

impl CrawlOptions {
    /// Sets the maximum directory recursion depth.
    pub fn with_max_depth(mut self, max_depth: usize) -> Self {
        self.max_depth = max_depth;
        self
    }

    /// Sets whether unreadable entries are skipped rather than aborting the crawl.
    pub fn with_skip_inaccessible(mut self, skip: bool) -> Self {
        self.skip_inaccessible = skip;
        self
    }

    /// Sets whether directory symlinks are traversed.
    pub fn with_follow_symlinks(mut self, follow: bool) -> Self {
        self.follow_symlinks = follow;
        self
    }

    /// Adds ignore glob patterns (e.g. `*.tmp`, `**/cache/**`, `**/.git/**`)
    pub fn with_ignore_patterns<I, S>(mut self, patterns: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        for p in patterns {
            let normalized = normalize_pattern(p.as_ref());
            let pat = Pattern::new(&normalized).map_err(|e| {
                OpenFimError::Other(format!("Invalid glob ignore pattern '{}': {}", p.as_ref(), e))
            })?;
            self.ignore_patterns.push(pat);
        }
        Ok(self)
    }

    /// Checks if a given path matches any configured ignore pattern
    pub fn is_ignored<P: AsRef<Path>>(&self, path: P) -> bool {
        let path_ref = path.as_ref();
        if self.ignore_patterns.is_empty() {
            return false;
        }

        let full = normalize_for_match(path_ref);
        let file_name = path_ref
            .file_name()
            .map(|n| normalize_for_match(Path::new(n)));

        for pattern in &self.ignore_patterns {
            if pattern.matches(&full) {
                return true;
            }
            // Also test matching just the filename component, so that a bare `*.tmp`
            // works without the caller having to write `**/*.tmp`.
            if let Some(ref name) = file_name {
                if pattern.matches(name) {
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
        let mut visited_dirs = std::collections::HashSet::new();
        self.crawl_recursive(&root_path, 0, hasher, &mut results, &mut visited_dirs)?;
        Ok(results)
    }

    fn crawl_recursive(
        &self,
        current_path: &Path,
        current_depth: usize,
        hasher: &mut StreamHasher,
        results: &mut Vec<FileMetadata>,
        visited_dirs: &mut std::collections::HashSet<(u64, u64)>,
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
                if self.options.skip_inaccessible {
                    return Ok(());
                }
                return Err(e);
            }
        };

        let is_dir = meta.is_dir;
        let is_symlink = meta.is_symlink;
        let identity_key = meta.identity_key();
        let has_identity = meta.has_stable_identity();

        results.push(meta);

        // If it's a directory (and not a symlink, unless follow_symlinks is true), walk children
        if is_dir && (!is_symlink || self.options.follow_symlinks) {
            // Guard against symlink recursion cycles.
            //
            // Only a genuine filesystem identity may be used as the key here. An
            // identity fabricated from mutable attributes (size, write time) collides
            // across unrelated directories, which would make the crawler silently
            // skip real directories it has never visited. When no stable identity is
            // available we skip the cycle check rather than risk those false skips;
            // `max_depth` still bounds the recursion.
            if has_identity && !visited_dirs.insert(identity_key) {
                return Ok(());
            }

            let entries = match std::fs::read_dir(current_path) {
                Ok(rd) => rd,
                Err(e) => {
                    if self.options.skip_inaccessible {
                        return Ok(());
                    }
                    return Err(OpenFimError::IoError {
                        path: current_path.to_path_buf(),
                        source: e,
                    });
                }
            };

            for entry in entries {
                let entry = match entry {
                    Ok(e) => e,
                    Err(e) => {
                        if self.options.skip_inaccessible {
                            continue;
                        }
                        return Err(OpenFimError::IoError {
                            path: current_path.to_path_buf(),
                            source: e,
                        });
                    }
                };
                let child_path = entry.path();
                self.crawl_recursive(&child_path, current_depth + 1, hasher, results, visited_dirs)?;
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

    #[test]
    fn test_directory_ignore_pattern_matches_native_separators() {
        // Regression guard: `glob::Pattern` only treats '/' as a separator, so without
        // normalization a `**/cache/**` rule never fires on a Windows path and every
        // configured directory exclusion is silently ignored.
        let dir = tempdir().unwrap();
        let root = dir.path();
        let cache_dir = root.join("cache");
        let keep_dir = root.join("conf");
        create_dir_all(&cache_dir).unwrap();
        create_dir_all(&keep_dir).unwrap();

        File::create(cache_dir.join("volatile.bin"))
            .unwrap()
            .write_all(b"churn")
            .unwrap();
        File::create(keep_dir.join("app.conf"))
            .unwrap()
            .write_all(b"key: value")
            .unwrap();

        let options = CrawlOptions::default()
            .with_ignore_patterns(vec!["**/cache/**"])
            .unwrap();
        let crawler = FileCrawler::new(options);
        let mut hasher = StreamHasher::default_sha256();
        let items = crawler.crawl(root, &mut hasher).unwrap();

        let names: Vec<String> = items
            .iter()
            .map(|m| m.path.file_name().unwrap().to_string_lossy().to_string())
            .collect();

        assert!(names.contains(&"app.conf".to_string()));
        assert!(
            !names.contains(&"volatile.bin".to_string()),
            "a file under an ignored directory was crawled: {:?}",
            names
        );
    }

    #[test]
    fn test_ignore_pattern_with_backslashes_is_accepted() {
        let dir = tempdir().unwrap();
        let sub = dir.path().join("logs");
        create_dir_all(&sub).unwrap();
        File::create(sub.join("audit.log"))
            .unwrap()
            .write_all(b"x")
            .unwrap();

        // An operator on Windows will naturally write the pattern with backslashes.
        let options = CrawlOptions::default()
            .with_ignore_patterns(vec![r"**\logs\**"])
            .unwrap();
        let crawler = FileCrawler::new(options);
        let mut hasher = StreamHasher::default_sha256();
        let items = crawler.crawl(dir.path(), &mut hasher).unwrap();

        assert!(
            !items
                .iter()
                .any(|m| m.path.file_name().unwrap() == "audit.log"),
            "backslash-written ignore pattern did not take effect"
        );
    }

    #[test]
    fn test_sibling_directories_are_both_crawled() {
        // Regression guard for cycle detection keyed on a fabricated identity: two
        // directories created in the same instant collided, so one was skipped.
        let dir = tempdir().unwrap();
        let root = dir.path();
        for name in ["d1", "d2", "d3", "d4"] {
            let sub = root.join(name);
            create_dir_all(&sub).unwrap();
            File::create(sub.join("marker.txt"))
                .unwrap()
                .write_all(b"m")
                .unwrap();
        }

        let crawler = FileCrawler::new(CrawlOptions::default());
        let mut hasher = StreamHasher::default_sha256();
        let items = crawler.crawl(root, &mut hasher).unwrap();

        let markers = items
            .iter()
            .filter(|m| m.path.file_name().unwrap() == "marker.txt")
            .count();
        assert_eq!(
            markers, 4,
            "expected all 4 sibling directories to be walked, found {} markers",
            markers
        );
    }

    #[test]
    fn test_max_depth_is_enforced() {
        let dir = tempdir().unwrap();
        let mut deep = dir.path().to_path_buf();
        for i in 0..6 {
            deep = deep.join(format!("level{}", i));
        }
        create_dir_all(&deep).unwrap();
        File::create(deep.join("buried.txt"))
            .unwrap()
            .write_all(b"deep")
            .unwrap();

        let crawler = FileCrawler::new(CrawlOptions::default().with_max_depth(2));
        let mut hasher = StreamHasher::default_sha256();
        let items = crawler.crawl(dir.path(), &mut hasher).unwrap();

        assert!(
            !items
                .iter()
                .any(|m| m.path.file_name().unwrap() == "buried.txt"),
            "max_depth did not bound the recursion"
        );
    }

    #[test]
    fn test_skip_inaccessible_is_the_default() {
        // A crawl of a real system path always hits something unreadable; aborting the
        // entire sweep on the first one would leave the operator with no baseline.
        assert!(
            CrawlOptions::default().skip_inaccessible,
            "an unreadable entry must not abort a whole baseline crawl by default"
        );
    }

    #[test]
    fn test_missing_root_errors_when_not_skipping() {
        let crawler = FileCrawler::new(CrawlOptions::default().with_skip_inaccessible(false));
        let mut hasher = StreamHasher::default_sha256();
        assert!(crawler
            .crawl("openfim-nonexistent-root-path", &mut hasher)
            .is_err());
    }

    #[test]
    fn test_missing_root_is_empty_when_skipping() {
        let crawler = FileCrawler::new(CrawlOptions::default());
        let mut hasher = StreamHasher::default_sha256();
        let items = crawler
            .crawl("openfim-nonexistent-root-path", &mut hasher)
            .unwrap();
        assert!(items.is_empty());
    }
}
