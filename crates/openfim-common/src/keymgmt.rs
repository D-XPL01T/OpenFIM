//! Chain key management: deriving a per-database key, and protecting it at rest.
//!
//! # The problem with one shared key
//!
//! Until now the audit chain was signed with whatever raw string `OPENFIM_HMAC_KEY`
//! contained. Operators deploying a fleet naturally use the same value everywhere, which
//! means **one compromised host yields the key to every host's audit log**. An attacker
//! who roots a single development box can forge the audit history of every production
//! machine.
//!
//! # Derivation
//!
//! The operator-supplied secret becomes a *root key*. The key actually used to sign a
//! given database is derived from it with HKDF-SHA256 over a random per-database salt:
//!
//! ```text
//!   chain_key = HKDF-SHA256(ikm = root_key, salt = per-database random, info = domain)
//! ```
//!
//! The salt is stored beside the chain it protects, which is fine — a salt is not a
//! secret. What it buys is **domain separation**: the derived key for host A reveals
//! nothing about the root key, and therefore nothing about host B's derived key. HKDF is
//! one-way, so recovering the root from a derived key is infeasible.
//!
//! This does not help against an attacker who has both the root key and the database;
//! nothing can, since the agent needs the derived key to append. It contains the blast
//! radius of a *derived* key leak, which is the realistic case: a stolen database, a
//! leaked backup, a shared log directory.
//!
//! # Protection at rest
//!
//! On Windows the root key file can additionally be wrapped with DPAPI
//! (`CryptProtectData`), which ties it to the machine or user account so that copying
//! the file to another host renders it useless. On Linux the equivalent would be the
//! kernel keyring or the Secret Service; neither is wired up yet, so there the
//! protection is file permissions plus derivation, and that is stated rather than
//! implied.

use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::{OpenFimError, Result};

/// HKDF `info` string. Domain-separates this derivation from any other use of the same
/// root key, so a key derived for the audit chain can never collide with one derived
/// for a different purpose later.
const CHAIN_KEY_INFO: &[u8] = b"openfim.chain-key.hkdf-sha256.v1";

/// Length of a derived chain key, matching HMAC-SHA256's block security level.
pub const CHAIN_KEY_LEN: usize = 32;

/// Length of the per-database salt.
pub const SALT_LEN: usize = 32;

/// How a database's chain key relates to the operator's secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyScheme {
    /// The operator's secret is used directly as the HMAC key.
    ///
    /// Retained only so databases written before derivation existed keep verifying.
    /// New databases never use this.
    Raw,
    /// HKDF-SHA256 over a per-database salt.
    HkdfSha256,
}

impl KeyScheme {
    /// Identifier persisted in the database.
    pub const fn id(&self) -> &'static str {
        match self {
            KeyScheme::Raw => "raw-v2",
            KeyScheme::HkdfSha256 => "hkdf-sha256-v1",
        }
    }

    /// Parses a persisted identifier.
    pub fn from_id(id: &str) -> Option<Self> {
        match id {
            "raw-v2" => Some(KeyScheme::Raw),
            "hkdf-sha256-v1" => Some(KeyScheme::HkdfSha256),
            _ => None,
        }
    }

    /// Human-readable description for startup output.
    pub const fn describe(&self) -> &'static str {
        match self {
            KeyScheme::Raw => {
                "raw (legacy: the supplied secret signs the chain directly; a leak \
                 compromises every host sharing it)"
            }
            KeyScheme::HkdfSha256 => {
                "HKDF-SHA256 with a per-database salt (a leaked derived key does not \
                 expose the root key or any other host's key)"
            }
        }
    }
}

/// Derives the chain key for one database.
pub fn derive_chain_key(root_key: &[u8], salt: &[u8]) -> Result<[u8; CHAIN_KEY_LEN]> {
    if root_key.is_empty() {
        return Err(OpenFimError::Other(
            "cannot derive a chain key from an empty root key".to_string(),
        ));
    }
    if salt.len() < 16 {
        return Err(OpenFimError::Other(format!(
            "chain key salt is {} bytes; at least 16 are required",
            salt.len()
        )));
    }

    let hk = Hkdf::<Sha256>::new(Some(salt), root_key);
    let mut out = [0u8; CHAIN_KEY_LEN];
    hk.expand(CHAIN_KEY_INFO, &mut out)
        .map_err(|e| OpenFimError::Other(format!("HKDF expansion failed: {}", e)))?;
    Ok(out)
}

/// Generates a fresh random salt.
pub fn generate_salt() -> [u8; SALT_LEN] {
    use rand_core::RngCore;
    let mut salt = [0u8; SALT_LEN];
    rand_core::OsRng.fill_bytes(&mut salt);
    salt
}

/// Resolves the effective chain key for a scheme.
pub fn chain_key_for(scheme: KeyScheme, root_key: &[u8], salt: Option<&[u8]>) -> Result<Vec<u8>> {
    match scheme {
        KeyScheme::Raw => Ok(root_key.to_vec()),
        KeyScheme::HkdfSha256 => {
            let salt = salt.ok_or_else(|| {
                OpenFimError::Other(
                    "the database records HKDF key derivation but holds no salt; it may \
                     be corrupt"
                        .to_string(),
                )
            })?;
            Ok(derive_chain_key(root_key, salt)?.to_vec())
        }
    }
}

// ---------------------------------------------------------------------------
// At-rest protection
// ---------------------------------------------------------------------------

/// Whether this platform can bind a key file to the machine.
pub const fn at_rest_protection_available() -> bool {
    cfg!(windows)
}

/// Describes the at-rest protection available here, for operator-facing output.
pub const fn at_rest_protection_note() -> &'static str {
    if cfg!(windows) {
        "DPAPI (CryptProtectData): a wrapped key file is useless if copied to another \
         machine or user account"
    } else {
        "file permissions and key derivation only; binding the key to the machine would \
         need the kernel keyring or Secret Service, which is not yet implemented"
    }
}

/// Wraps key material so that it is only usable on this machine.
///
/// On Windows this is DPAPI with machine scope. Elsewhere it returns the input
/// unchanged, and [`at_rest_protection_available`] reports `false` so callers can say so
/// rather than implying a protection that is not there.
pub fn protect_at_rest(plaintext: &[u8]) -> Result<Vec<u8>> {
    #[cfg(windows)]
    {
        windows_dpapi::protect(plaintext)
    }
    #[cfg(not(windows))]
    {
        Ok(plaintext.to_vec())
    }
}

/// Unwraps key material wrapped by [`protect_at_rest`].
pub fn unprotect_at_rest(wrapped: &[u8]) -> Result<Vec<u8>> {
    #[cfg(windows)]
    {
        windows_dpapi::unprotect(wrapped)
    }
    #[cfg(not(windows))]
    {
        Ok(wrapped.to_vec())
    }
}

/// Magic prefix marking a DPAPI-wrapped key file, so a wrapped and an unwrapped file
/// can be told apart without guessing.
pub const WRAPPED_KEY_MAGIC: &[u8] = b"OPENFIM-DPAPI-V1\n";

/// True when the bytes look like a wrapped key file.
pub fn is_wrapped(bytes: &[u8]) -> bool {
    bytes.starts_with(WRAPPED_KEY_MAGIC)
}

/// Wraps and prefixes key material for storage.
pub fn wrap_for_storage(plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut out = WRAPPED_KEY_MAGIC.to_vec();
    out.extend_from_slice(&protect_at_rest(plaintext)?);
    Ok(out)
}

/// Reads key material that may or may not be wrapped.
pub fn unwrap_from_storage(bytes: &[u8]) -> Result<Vec<u8>> {
    if let Some(body) = bytes.strip_prefix(WRAPPED_KEY_MAGIC) {
        if !at_rest_protection_available() {
            return Err(OpenFimError::Other(
                "this key file is DPAPI-wrapped but this platform cannot unwrap it. \
                 Unwrap it on the Windows host that created it."
                    .to_string(),
            ));
        }
        unprotect_at_rest(body)
    } else {
        Ok(bytes.to_vec())
    }
}

#[cfg(windows)]
mod windows_dpapi {
    use super::*;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_LOCAL_MACHINE,
        CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    fn blob(data: &[u8]) -> CRYPT_INTEGER_BLOB {
        CRYPT_INTEGER_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        }
    }

    /// Copies an output blob out and frees the OS allocation exactly once.
    unsafe fn take(out: &CRYPT_INTEGER_BLOB) -> Vec<u8> {
        let slice = std::slice::from_raw_parts(out.pbData, out.cbData as usize);
        let owned = slice.to_vec();
        LocalFree(out.pbData as *mut core::ffi::c_void);
        owned
    }

    pub fn protect(plaintext: &[u8]) -> Result<Vec<u8>> {
        let input = blob(plaintext);
        let mut output = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };

        // LOCAL_MACHINE scope so the agent can read the key when running as a service
        // account, rather than only as the interactive user who created it.
        // UI_FORBIDDEN because a daemon must never block on a prompt.
        // SAFETY: both blobs are valid; on success the call allocates `output.pbData`,
        // which `take` frees.
        let ok = unsafe {
            CryptProtectData(
                &input,
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        };

        if ok == 0 {
            return Err(OpenFimError::Other(format!(
                "DPAPI CryptProtectData failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        // SAFETY: the call succeeded, so `output` holds an allocated buffer.
        Ok(unsafe { take(&output) })
    }

    pub fn unprotect(wrapped: &[u8]) -> Result<Vec<u8>> {
        let input = blob(wrapped);
        let mut output = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };

        // SAFETY: as above.
        let ok = unsafe {
            CryptUnprotectData(
                &input,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        };

        if ok == 0 {
            return Err(OpenFimError::Other(format!(
                "DPAPI CryptUnprotectData failed: {}. The key file may have been created \
                 on a different machine, which is exactly what this protection is for.",
                std::io::Error::last_os_error()
            )));
        }
        // SAFETY: the call succeeded, so `output` holds an allocated buffer.
        Ok(unsafe { take(&output) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivation_is_deterministic() {
        let salt = [7u8; SALT_LEN];
        let a = derive_chain_key(b"root-secret", &salt).unwrap();
        let b = derive_chain_key(b"root-secret", &salt).unwrap();
        assert_eq!(a, b, "the same inputs must yield the same chain key");
        assert_eq!(a.len(), CHAIN_KEY_LEN);
    }

    #[test]
    fn different_salts_give_different_keys() {
        // The property that contains blast radius: two hosts sharing a root key must not
        // share a chain key, so a leak from one does not forge the other's audit log.
        let root = b"fleet-wide-root-secret";
        let host_a = derive_chain_key(root, &generate_salt()).unwrap();
        let host_b = derive_chain_key(root, &generate_salt()).unwrap();
        assert_ne!(
            host_a, host_b,
            "two databases with the same root key derived identical chain keys"
        );
    }

    #[test]
    fn different_roots_give_different_keys() {
        let salt = [3u8; SALT_LEN];
        assert_ne!(
            derive_chain_key(b"root-one", &salt).unwrap(),
            derive_chain_key(b"root-two", &salt).unwrap()
        );
    }

    #[test]
    fn derived_key_does_not_contain_the_root() {
        // HKDF is one-way; this is a sanity check that we are not accidentally passing
        // the root through, which would defeat the whole point.
        let root = b"a-very-distinctive-root-key-value";
        let derived = derive_chain_key(root, &[9u8; SALT_LEN]).unwrap();
        assert!(
            !derived.windows(root.len()).any(|w| w == root),
            "the derived key contains the root key verbatim"
        );
    }

    #[test]
    fn empty_root_is_refused() {
        assert!(derive_chain_key(b"", &[1u8; SALT_LEN]).is_err());
    }

    #[test]
    fn short_salt_is_refused() {
        // A short salt weakens domain separation; refuse rather than silently accept.
        assert!(derive_chain_key(b"root", &[1u8; 8]).is_err());
        assert!(derive_chain_key(b"root", &[1u8; 16]).is_ok());
    }

    #[test]
    fn generated_salts_are_not_repeated() {
        let a = generate_salt();
        let b = generate_salt();
        assert_ne!(a, b, "salt generation is not random");
        assert_ne!(a, [0u8; SALT_LEN], "salt is all zeroes");
    }

    #[test]
    fn scheme_ids_round_trip() {
        for scheme in [KeyScheme::Raw, KeyScheme::HkdfSha256] {
            assert_eq!(KeyScheme::from_id(scheme.id()), Some(scheme));
            assert!(!scheme.describe().is_empty());
        }
        assert_eq!(KeyScheme::from_id("nonsense"), None);
    }

    #[test]
    fn raw_scheme_passes_the_root_through_for_legacy_databases() {
        let key = chain_key_for(KeyScheme::Raw, b"legacy-secret", None).unwrap();
        assert_eq!(key, b"legacy-secret");
    }

    #[test]
    fn hkdf_scheme_requires_a_salt() {
        assert!(chain_key_for(KeyScheme::HkdfSha256, b"root", None).is_err());
        let salt = generate_salt();
        assert!(chain_key_for(KeyScheme::HkdfSha256, b"root", Some(&salt)).is_ok());
    }

    #[test]
    fn unwrapped_key_material_passes_through() {
        // A plain key file must keep working; wrapping is additive.
        let plain = b"plain-root-key";
        assert_eq!(unwrap_from_storage(plain).unwrap(), plain);
        assert!(!is_wrapped(plain));
    }

    #[test]
    fn wrap_round_trips_on_this_platform() {
        let secret = b"root-key-material-to-protect";
        let stored = wrap_for_storage(secret).unwrap();
        assert!(
            is_wrapped(&stored),
            "stored form should carry the magic prefix"
        );
        assert_eq!(unwrap_from_storage(&stored).unwrap(), secret);
    }

    #[cfg(windows)]
    #[test]
    fn windows_wrapping_actually_changes_the_bytes() {
        // Guard against the no-op fallback silently being used on a platform that does
        // support protection, which would claim a guarantee it is not providing.
        let secret = b"root-key-material-to-protect";
        let stored = wrap_for_storage(secret).unwrap();
        let body = &stored[WRAPPED_KEY_MAGIC.len()..];
        assert_ne!(body, secret, "DPAPI did not transform the key material");
        assert!(
            body.len() > secret.len(),
            "ciphertext should carry DPAPI metadata"
        );
        assert!(at_rest_protection_available());
    }

    #[cfg(windows)]
    #[test]
    fn windows_rejects_corrupt_wrapped_material() {
        let stored = wrap_for_storage(b"secret").unwrap();
        let mut corrupt = stored.clone();
        let n = corrupt.len();
        corrupt[n - 1] ^= 0xFF;
        assert!(
            unwrap_from_storage(&corrupt).is_err(),
            "corrupt DPAPI material must fail rather than yield garbage"
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn non_windows_reports_no_at_rest_protection() {
        // Stating the absence is the point: a caller must be able to tell the operator
        // that the key is protected by permissions alone.
        assert!(!at_rest_protection_available());
        assert!(at_rest_protection_note().contains("not yet implemented"));
    }
}
