use sha2::{Digest, Sha256, Sha512};
use std::fs::File;
use std::io::Read;
use std::path::Path;

use crate::error::{OpenFimError, Result};
use crate::fsident::{self, FsIdentity};
use crate::rate_limiter::TokenBucket;

/// Default read buffer size for streaming file reads (64 KB bounded memory window)
pub const DEFAULT_BUFFER_SIZE: usize = 64 * 1024;

/// Supported Cryptographic Hashing Algorithms
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HashAlgorithm {
    #[default]
    Sha256,
    Blake3,
    Sha512,
}

impl std::str::FromStr for HashAlgorithm {
    type Err = OpenFimError;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "sha256" | "sha-256" => Ok(HashAlgorithm::Sha256),
            "blake3" => Ok(HashAlgorithm::Blake3),
            "sha512" | "sha-512" => Ok(HashAlgorithm::Sha512),
            "md5" | "sha1" | "sha-1" => Err(OpenFimError::UnsupportedAlgorithm(format!(
                "Algorithm '{}' is cryptographically deprecated and prohibited for integrity baseline enforcement.",
                s
            ))),
            _ => Err(OpenFimError::UnsupportedAlgorithm(s.to_string())),
        }
    }
}

/// File identity used to detect TOCTOU file-substitution attacks.
///
/// This is an alias for the shared [`FsIdentity`] resolver so that the hasher, the
/// metadata extractor and the crawler all key off exactly the same notion of
/// identity. See [`crate::fsident`] for why a stable, non-content-derived identity
/// matters here.
pub type FileIdentity = FsIdentity;

/// Extracts the platform-specific identity of an open file handle
fn extract_file_identity(file: &File) -> Result<FileIdentity> {
    Ok(fsident::identity_of_handle(file))
}

/// Hint to the OS that this handle will be read front-to-back exactly once.
fn advise_sequential(_file: &File) {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        // SAFETY: the fd is owned by `_file` and remains open for the call's duration.
        unsafe {
            libc::posix_fadvise(_file.as_raw_fd(), 0, 0, libc::POSIX_FADV_SEQUENTIAL);
        }
    }
}

/// Advise the OS to drop the pages this scan just pulled in, so a full integrity
/// sweep does not evict the working set of the production workload on the host.
///
/// This must run *after* the read completes: issuing `DONTNEED` before reading has
/// no useful effect, because the pages being protected have not been faulted in yet.
fn advise_dontneed(_file: &File) {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        // SAFETY: the fd is owned by `_file` and remains open for the call's duration.
        unsafe {
            libc::posix_fadvise(_file.as_raw_fd(), 0, 0, libc::POSIX_FADV_DONTNEED);
        }
    }
}

/// Opens a file for integrity scanning, requesting a sequential-access cache policy.
fn open_for_scan(path: &Path) -> std::io::Result<File> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // FILE_FLAG_SEQUENTIAL_SCAN tells the Windows cache manager to evict pages
        // aggressively behind a one-pass read, the counterpart to POSIX_FADV_DONTNEED.
        const FILE_FLAG_SEQUENTIAL_SCAN: u32 = 0x0800_0000;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_SEQUENTIAL_SCAN)
            .open(path)
    }

    #[cfg(not(windows))]
    {
        File::open(path)
    }
}

/// Streaming digest engine. Only the selected algorithm's state is allocated.
enum DigestEngine {
    Sha256(Sha256),
    Sha512(Sha512),
    // Boxed because blake3::Hasher carries a large inline state buffer that would
    // otherwise inflate this enum (and every StreamHasher call frame) by ~2 KB.
    Blake3(Box<blake3::Hasher>),
}

impl DigestEngine {
    fn new(algorithm: HashAlgorithm) -> Self {
        match algorithm {
            HashAlgorithm::Sha256 => DigestEngine::Sha256(Sha256::new()),
            HashAlgorithm::Sha512 => DigestEngine::Sha512(Sha512::new()),
            HashAlgorithm::Blake3 => DigestEngine::Blake3(Box::new(blake3::Hasher::new())),
        }
    }

    #[inline]
    fn update(&mut self, data: &[u8]) {
        match self {
            DigestEngine::Sha256(h) => h.update(data),
            DigestEngine::Sha512(h) => h.update(data),
            DigestEngine::Blake3(h) => {
                h.update(data);
            }
        }
    }

    fn finalize(self) -> String {
        match self {
            DigestEngine::Sha256(h) => hex::encode(h.finalize()),
            DigestEngine::Sha512(h) => hex::encode(h.finalize()),
            DigestEngine::Blake3(h) => h.finalize().to_hex().to_string(),
        }
    }
}

/// Result of a file hashing operation
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HashResult {
    pub algorithm: HashAlgorithm,
    pub hex_digest: String,
    pub bytes_read: u64,
    /// Secondary BLAKE3 digest, present only when `with_secondary_blake3` was enabled
    /// and the primary algorithm is not already BLAKE3.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blake3_digest: Option<String>,
}

/// StreamHasher: Bounded memory, rate-throttled, TOCTOU-protected file hasher
pub struct StreamHasher {
    algorithm: HashAlgorithm,
    buffer_size: usize,
    rate_limiter: TokenBucket,
    secondary_blake3: bool,
}

impl StreamHasher {
    /// Creates a new StreamHasher with the given algorithm and rate limiter
    pub fn new(algorithm: HashAlgorithm, rate_limiter: TokenBucket) -> Self {
        Self {
            algorithm,
            buffer_size: DEFAULT_BUFFER_SIZE,
            rate_limiter,
            secondary_blake3: false,
        }
    }

    /// Creates a default SHA-256 StreamHasher with no artificial rate throttling
    pub fn default_sha256() -> Self {
        Self::new(HashAlgorithm::Sha256, TokenBucket::unlimited())
    }

    /// Sets a custom chunk buffer size (e.g. 64 KB, 128 KB)
    pub fn with_buffer_size(mut self, size: usize) -> Self {
        self.buffer_size = size.max(1024);
        self
    }

    /// Additionally computes a BLAKE3 digest in the same single read pass.
    ///
    /// Off by default: enabling it roughly doubles per-byte CPU cost, but it is the
    /// only way to populate the baseline's `blake3` column without re-reading the file.
    pub fn with_secondary_blake3(mut self, enabled: bool) -> Self {
        self.secondary_blake3 = enabled;
        self
    }

    /// Returns the primary algorithm this hasher computes.
    pub fn algorithm(&self) -> HashAlgorithm {
        self.algorithm
    }

    /// Returns whether a secondary BLAKE3 digest is computed alongside the primary.
    pub fn computes_secondary_blake3(&self) -> bool {
        self.secondary_blake3 && self.algorithm != HashAlgorithm::Blake3
    }

    /// Hashes the target file, enforcing page-cache eviction and TOCTOU verification
    pub fn hash_file<P: AsRef<Path>>(&mut self, path: P) -> Result<HashResult> {
        let path_ref = path.as_ref();
        let mut file = open_for_scan(path_ref).map_err(|e| OpenFimError::IoError {
            path: path_ref.to_path_buf(),
            source: e,
        })?;

        // 1. Identity of the object we actually opened, captured from the handle itself
        let opened_identity = extract_file_identity(&file)?;

        // 2. Ask for a sequential-access cache policy before the read begins
        advise_sequential(&file);

        // 3. Initialize only the digest state we actually need
        let mut engine = DigestEngine::new(self.algorithm);
        let mut secondary = if self.computes_secondary_blake3() {
            Some(Box::new(blake3::Hasher::new()))
        } else {
            None
        };

        let mut buffer = vec![0u8; self.buffer_size];
        let mut total_bytes_read = 0u64;

        loop {
            let bytes_read = file.read(&mut buffer).map_err(|e| OpenFimError::IoError {
                path: path_ref.to_path_buf(),
                source: e,
            })?;

            if bytes_read == 0 {
                break;
            }

            // Apply rate limiting throttle
            self.rate_limiter.consume(bytes_read);

            let chunk = &buffer[..bytes_read];
            engine.update(chunk);
            if let Some(ref mut b3) = secondary {
                b3.update(chunk);
            }

            total_bytes_read += bytes_read as u64;
        }

        // 4. TOCTOU validation.
        //
        // Re-stat the *path* and compare it against the identity of the handle we read.
        // This is the check that actually matters: an attacker performs substitution by
        // repointing the path (rename, symlink swap, hardlink replace) at a different
        // object, which leaves our open handle — and therefore its own metadata — intact.
        // Comparing the handle against itself before and after the read, as a naive
        // implementation does, can never observe that attack.
        let post_identity = extract_file_identity(&file)?;
        if !opened_identity.refers_to_same(&post_identity) {
            advise_dontneed(&file);
            return Err(OpenFimError::ToctouSubstitutionDetected {
                path: path_ref.to_path_buf(),
                expected_identity: opened_identity.to_string(),
                actual_identity: post_identity.to_string(),
            });
        }

        if opened_identity.is_stable {
            let path_identity = fsident::identity_of_path(path_ref);
            if path_identity.is_stable && !opened_identity.refers_to_same(&path_identity) {
                advise_dontneed(&file);
                return Err(OpenFimError::ToctouSubstitutionDetected {
                    path: path_ref.to_path_buf(),
                    expected_identity: opened_identity.to_string(),
                    actual_identity: path_identity.to_string(),
                });
            }
        }

        // 5. Drop the pages this scan faulted in, now that the read is complete
        advise_dontneed(&file);

        // 6. Finalize hex digests
        let hex_digest = engine.finalize();
        let blake3_digest = secondary.map(|h| h.finalize().to_hex().to_string());

        Ok(HashResult {
            algorithm: self.algorithm,
            hex_digest,
            bytes_read: total_bytes_read,
            blake3_digest,
        })
    }

    /// Pure in-memory hashing for strings/buffers
    pub fn hash_bytes(algorithm: HashAlgorithm, data: &[u8]) -> String {
        let mut engine = DigestEngine::new(algorithm);
        engine.update(data);
        engine.finalize()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    // Published FIPS 180-4 / NIST CAVP SHA-256 test vectors. These are hard-coded
    // constants on purpose: deriving the expectation from the same sha2 crate under
    // test would make the assertion tautological and unable to catch a regression.
    const NIST_SHA256_EMPTY: &str =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const NIST_SHA256_ABC: &str =
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const NIST_SHA256_448BIT: &str =
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1";
    const SHA256_FOX: &str = "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592";
    const NIST_SHA512_ABC: &str = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";
    // Official BLAKE3 reference test vectors (BLAKE3-team/BLAKE3 test_vectors.json,
    // unkeyed `hash` field truncated to the default 32-byte output length).
    const BLAKE3_EMPTY: &str = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262";
    const BLAKE3_8_BYTES: &str = "2351207d04fc16ade43ccab08600939c7c1fa70a5c0aaca76063d04c3228eaeb";

    #[test]
    fn test_nist_sha256_vectors() {
        assert_eq!(
            StreamHasher::hash_bytes(HashAlgorithm::Sha256, b""),
            NIST_SHA256_EMPTY
        );
        assert_eq!(
            StreamHasher::hash_bytes(HashAlgorithm::Sha256, b"abc"),
            NIST_SHA256_ABC
        );
        assert_eq!(
            StreamHasher::hash_bytes(
                HashAlgorithm::Sha256,
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            ),
            NIST_SHA256_448BIT
        );
        assert_eq!(
            StreamHasher::hash_bytes(
                HashAlgorithm::Sha256,
                b"The quick brown fox jumps over the lazy dog"
            ),
            SHA256_FOX
        );
    }

    #[test]
    fn test_nist_sha512_vector() {
        assert_eq!(
            StreamHasher::hash_bytes(HashAlgorithm::Sha512, b"abc"),
            NIST_SHA512_ABC
        );
    }

    #[test]
    fn test_blake3_reference_vector() {
        // Hard-coded reference digests rather than a call back into the blake3 crate.
        assert_eq!(
            StreamHasher::hash_bytes(HashAlgorithm::Blake3, b""),
            BLAKE3_EMPTY
        );
        // The official vectors use a repeating 0..=250 byte pattern; for input_len 8
        // that is simply the bytes 0x00 through 0x07.
        let input: Vec<u8> = (0u8..8).collect();
        assert_eq!(
            StreamHasher::hash_bytes(HashAlgorithm::Blake3, &input),
            BLAKE3_8_BYTES
        );
    }

    #[test]
    fn test_deprecated_algorithms_rejected() {
        assert!("md5".parse::<HashAlgorithm>().is_err());
        assert!("sha1".parse::<HashAlgorithm>().is_err());
        assert!("sha-1".parse::<HashAlgorithm>().is_err());
        assert!("sha256".parse::<HashAlgorithm>().is_ok());
        assert!("blake3".parse::<HashAlgorithm>().is_ok());
        assert!("sha512".parse::<HashAlgorithm>().is_ok());
    }

    #[test]
    fn test_chunked_file_hashing_matches_known_digest() {
        let mut temp_file = NamedTempFile::new().expect("Failed to create temp file");
        // 'a' repeated 1,000,000 times is a published NIST SHA-256 long-message vector,
        // and at ~1 MB it spans many 32 KB read chunks.
        let payload = vec![b'a'; 1_000_000];
        temp_file.write_all(&payload).unwrap();
        temp_file.flush().unwrap();

        let mut hasher = StreamHasher::default_sha256().with_buffer_size(32 * 1024);
        let result = hasher.hash_file(temp_file.path()).expect("Hashing failed");

        assert_eq!(result.algorithm, HashAlgorithm::Sha256);
        assert_eq!(result.bytes_read, 1_000_000);
        assert_eq!(
            result.hex_digest,
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
        assert!(result.blake3_digest.is_none());
    }

    #[test]
    fn test_streaming_matches_single_shot_for_small_file() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file
            .write_all(b"The quick brown fox jumps over the lazy dog")
            .unwrap();
        temp_file.flush().unwrap();

        let mut hasher = StreamHasher::default_sha256().with_buffer_size(1024);
        let result = hasher.hash_file(temp_file.path()).unwrap();
        assert_eq!(result.hex_digest, SHA256_FOX);
    }

    #[test]
    fn test_secondary_blake3_single_pass() {
        let mut temp_file = NamedTempFile::new().unwrap();
        let payload = b"OpenFIM dual-digest single-pass verification payload";
        temp_file.write_all(payload).unwrap();
        temp_file.flush().unwrap();

        let mut hasher = StreamHasher::default_sha256()
            .with_secondary_blake3(true)
            .with_buffer_size(16);
        let result = hasher.hash_file(temp_file.path()).unwrap();

        assert_eq!(
            result.hex_digest,
            StreamHasher::hash_bytes(HashAlgorithm::Sha256, payload)
        );
        assert_eq!(
            result.blake3_digest.as_deref(),
            Some(StreamHasher::hash_bytes(HashAlgorithm::Blake3, payload).as_str()),
            "chunked secondary BLAKE3 must equal the single-shot digest"
        );
    }

    #[test]
    fn test_secondary_blake3_not_duplicated_when_primary() {
        let hasher = StreamHasher::new(HashAlgorithm::Blake3, TokenBucket::unlimited())
            .with_secondary_blake3(true);
        assert!(
            !hasher.computes_secondary_blake3(),
            "BLAKE3 must not be computed twice when it is already the primary algorithm"
        );
    }

    #[test]
    fn test_file_identity_is_stable_on_this_platform() {
        let temp_file = NamedTempFile::new().unwrap();
        let file = File::open(temp_file.path()).unwrap();
        let id = extract_file_identity(&file).unwrap();
        assert!(
            id.is_stable,
            "neither Unix st_dev/st_ino nor Windows volume serial + file index resolved; \
             TOCTOU substitution detection would be silently disabled"
        );
    }

    #[test]
    fn test_distinct_files_have_distinct_identities() {
        let a = NamedTempFile::new().unwrap();
        let b = NamedTempFile::new().unwrap();
        let id_a = extract_file_identity(&File::open(a.path()).unwrap()).unwrap();
        let id_b = extract_file_identity(&File::open(b.path()).unwrap()).unwrap();

        assert!(
            !id_a.refers_to_same(&id_b),
            "two different files reported the same identity; substitution detection is ineffective"
        );
    }

    #[test]
    fn test_identity_survives_content_modification() {
        // Regression guard: the identity must be derived from the filesystem object,
        // not from mutable attributes like size or write time. Deriving it from those
        // makes every ordinary content change look like a substitution attack.
        let mut temp = NamedTempFile::new().unwrap();
        temp.write_all(b"initial").unwrap();
        temp.flush().unwrap();

        let before = extract_file_identity(&File::open(temp.path()).unwrap()).unwrap();

        temp.write_all(b" and appended content that changes size and mtime")
            .unwrap();
        temp.flush().unwrap();

        let after = extract_file_identity(&File::open(temp.path()).unwrap()).unwrap();

        assert!(
            before.refers_to_same(&after),
            "identity changed after an ordinary write: {} -> {}",
            before,
            after
        );
    }

    #[test]
    fn test_hashing_a_modified_file_does_not_report_substitution() {
        // End-to-end guard for the same defect: hashing a file whose content changed
        // must succeed, not fail with a spurious ToctouSubstitutionDetected error.
        let mut temp = NamedTempFile::new().unwrap();
        temp.write_all(b"baseline content").unwrap();
        temp.flush().unwrap();

        let mut hasher = StreamHasher::default_sha256();
        hasher.hash_file(temp.path()).expect("first hash failed");

        temp.write_all(b" tampered by adversary").unwrap();
        temp.flush().unwrap();

        let second = hasher
            .hash_file(temp.path())
            .expect("hashing a legitimately modified file must not report substitution");
        assert_eq!(second.bytes_read, 38);
    }
}
