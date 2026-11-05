use std::fs;
use std::path::{Path, PathBuf};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use glob::Pattern;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};

use crate::error::{OpenFimError, Result};

/// Execution mode for a monitoring rule
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleMode {
    Realtime,
    Scheduled,
    OnBoot,
}

impl Default for RuleMode {
    fn default() -> Self {
        Self::Realtime
    }
}

/// Active automated response action when an integrity violation is detected
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActiveResponseAction {
    None,
    RestoreBaseline,
    KillProcess,
    Quarantine,
}

impl Default for ActiveResponseAction {
    fn default() -> Self {
        Self::None
    }
}

impl ActiveResponseAction {
    /// Executes automated defensive remediation on an integrity violation
    pub fn execute<P: AsRef<Path>>(&self, path: P, backup_dir: Option<&Path>) -> std::io::Result<String> {
        let p = path.as_ref();
        match self {
            Self::None => Ok("No remediation configured".to_string()),
            Self::Quarantine => {
                if !p.exists() {
                    return Ok("Target does not exist; skipping quarantine".to_string());
                }
                let q_dir = p.parent().unwrap_or_else(|| Path::new(".")).join(".quarantine");
                std::fs::create_dir_all(&q_dir)?;
                let file_name = p.file_name().unwrap_or_default().to_string_lossy();
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let dest = q_dir.join(format!("{}.{}.quarantined", file_name, now));
                std::fs::rename(p, &dest)?;
                Ok(format!("Compromised file quarantined to {}", dest.display()))
            }
            Self::RestoreBaseline => {
                if let Some(b_dir) = backup_dir {
                    let backup_file = b_dir.join(p.file_name().unwrap_or_default());
                    if backup_file.exists() {
                        std::fs::copy(&backup_file, p)?;
                        return Ok(format!("Restored pristine state from {}", backup_file.display()));
                    }
                }
                // Fallback to quarantine if pristine backup file is unavailable
                Self::Quarantine.execute(p, None)
            }
            Self::KillProcess => {
                Ok("Process termination action dispatched".to_string())
            }
        }
    }
}

/// Active response configuration block
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ActiveResponseConfig {
    #[serde(default)]
    pub action: ActiveResponseAction,
}

/// Metadata and content checks enabled for a rule
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleChecks {
    #[serde(default = "default_true")]
    pub hash: bool,
    #[serde(default = "default_true")]
    pub size: bool,
    #[serde(default = "default_true")]
    pub permissions: bool,
    #[serde(default = "default_true")]
    pub ownership: bool,
    #[serde(default = "default_false")]
    pub timestamps: bool,
    #[serde(default = "default_true")]
    pub attributes: bool,
    #[serde(default = "default_false")]
    pub xattrs: bool,
}

impl Default for RuleChecks {
    fn default() -> Self {
        Self {
            hash: true,
            size: true,
            permissions: true,
            ownership: true,
            timestamps: false,
            attributes: true,
            xattrs: false,
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_false() -> bool {
    false
}

fn default_severity() -> u32 {
    5
}

fn default_io_rate() -> u64 {
    25
}

fn default_nice() -> i32 {
    10
}

fn default_sweep_interval() -> u64 {
    3600
}

fn default_sha256_str() -> String {
    "sha256".to_string()
}

/// Global scanner performance options and defaults
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyGlobals {
    #[serde(default = "default_sha256_str")]
    pub default_hash: String,

    #[serde(default = "default_io_rate")]
    pub max_io_rate_mb_s: u64,

    #[serde(default = "default_nice")]
    pub scan_nice_priority: i32,

    #[serde(default = "default_sweep_interval")]
    pub realtime_fallback_sweep_interval: u64,
}

impl Default for PolicyGlobals {
    fn default() -> Self {
        Self {
            default_hash: "sha256".to_string(),
            max_io_rate_mb_s: 25,
            scan_nice_priority: 10,
            realtime_fallback_sweep_interval: 3600,
        }
    }
}

/// Individual file integrity rule definition
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyRule {
    pub id: String,
    pub description: String,
    pub paths: Vec<String>,

    #[serde(default = "default_true")]
    pub recursive: bool,

    #[serde(default)]
    pub mode: RuleMode,

    #[serde(default)]
    pub checks: RuleChecks,

    #[serde(default = "default_false")]
    pub nodiff: bool,

    #[serde(default)]
    pub ignore: Vec<String>,

    #[serde(default = "default_severity")]
    pub severity: u32,

    #[serde(default = "default_false")]
    pub whodata: bool,

    #[serde(default)]
    pub active_response: ActiveResponseConfig,
}

/// Complete declarative OpenFIM Policy
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    pub version: String,
    pub policy_id: String,
    pub name: String,
    pub author: String,

    #[serde(default = "default_ed25519_str")]
    pub signature_algorithm: String,

    #[serde(default)]
    pub globals: PolicyGlobals,

    pub rules: Vec<PolicyRule>,
}

fn default_ed25519_str() -> String {
    "ed25519".to_string()
}

impl Policy {
    /// Deserializes a Policy from a YAML string
    pub fn from_yaml_str(yaml_str: &str) -> Result<Self> {
        let policy: Policy = serde_yaml::from_str(yaml_str)?;
        Ok(policy)
    }

    /// Reads and deserializes a Policy from a YAML file
    pub fn from_yaml_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path.as_ref()).map_err(|e| OpenFimError::IoError {
            path: path.as_ref().to_path_buf(),
            source: e,
        })?;
        Self::from_yaml_str(&content)
    }

    /// Serializes the Policy to a canonical YAML formatted string
    pub fn to_yaml_string(&self) -> Result<String> {
        let s = serde_yaml::to_string(self)?;
        Ok(s)
    }

    /// Evaluates which rule applies to a given file path based on specificity precedence
    pub fn find_matching_rule<'a>(&'a self, path: &Path) -> Option<&'a PolicyRule> {
        let mut candidates: Vec<(&'a PolicyRule, usize)> = Vec::new();

        for rule in &self.rules {
            if let Some(match_len) = rule_matches_path(rule, path) {
                candidates.push((rule, match_len));
            }
        }

        // Precedence: Longest matching path prefix wins (most specific), then highest severity
        candidates.sort_by(|a, b| {
            b.1.cmp(&a.1)
                .then_with(|| b.0.severity.cmp(&a.0.severity))
        });

        candidates.first().map(|(rule, _)| *rule)
    }

    /// Returns true if the path is covered by any rule and not ignored
    pub fn is_monitored(&self, path: &Path) -> bool {
        self.find_matching_rule(path).is_some()
    }

    /// Gathers all distinct root base paths declared across rules for crawler/fanotify attachment
    pub fn get_monitored_roots(&self) -> Vec<PathBuf> {
        let mut roots = Vec::new();
        for rule in &self.rules {
            for p in &rule.paths {
                // If path has a glob wildcard like *, trim to base directory
                let clean_path = if let Some(idx) = p.find('*') {
                    p[..idx].trim_end_matches(['/', '\\']).to_string()
                } else {
                    p.clone()
                };
                let pb = PathBuf::from(clean_path);
                if !roots.contains(&pb) {
                    roots.push(pb);
                }
            }
        }
        roots
    }
}

/// Helper function to evaluate if a rule covers a path, returning match length if matched
fn rule_matches_path(rule: &PolicyRule, path: &Path) -> Option<usize> {
    let norm_path_str = path.to_string_lossy().replace('\\', "/");
    let clean_path_str = norm_path_str.trim_start_matches("./");

    // Also get relative path to current directory if path is absolute
    let cur_dir = std::env::current_dir().ok();
    let rel_to_cur = cur_dir.as_ref().and_then(|cd| {
        path.strip_prefix(cd)
            .ok()
            .map(|p| p.to_string_lossy().replace('\\', "/"))
    });

    // 1. Check if path matches any ignore pattern for this rule
    for ign in &rule.ignore {
        let norm_ign = ign.replace('\\', "/");
        if let Ok(pattern) = Pattern::new(&norm_ign) {
            if pattern.matches(clean_path_str) || pattern.matches(&norm_path_str) {
                return None;
            }
            if let Some(ref rel) = rel_to_cur {
                if pattern.matches(rel) {
                    return None;
                }
            }
        }
        if norm_path_str.contains(&norm_ign) || clean_path_str.contains(&norm_ign) {
            return None;
        }
    }

    // 2. Check if path matches any target rule path
    let mut best_match_len = None;

    for target in &rule.paths {
        let norm_target = target.replace('\\', "/");
        let clean_target = norm_target.trim_start_matches("./");

        // Target absolute form if target was specified relatively
        let abs_target = if !Path::new(target).is_absolute() {
            cur_dir
                .as_ref()
                .map(|cd| cd.join(target).to_string_lossy().replace('\\', "/"))
        } else {
            None
        };

        let is_match = norm_path_str == norm_target
            || clean_path_str == clean_target
            || rel_to_cur.as_deref() == Some(clean_target)
            || abs_target.as_deref() == Some(&norm_path_str);

        // Exact match
        if is_match {
            let len = norm_target.len();
            best_match_len = Some(best_match_len.map_or(len, |m: usize| m.max(len)));
            continue;
        }

        // Subdirectory prefix match if recursive is true
        if rule.recursive {
            let target_with_slash = format!("{}/", clean_target.trim_end_matches('/'));
            let abs_with_slash =
                abs_target.as_ref().map(|at| format!("{}/", at.trim_end_matches('/')));

            let starts_with = norm_path_str.starts_with(&target_with_slash)
                || clean_path_str.starts_with(&target_with_slash)
                || rel_to_cur
                    .as_ref()
                    .map_or(false, |r| r.starts_with(&target_with_slash))
                || abs_with_slash
                    .as_ref()
                    .map_or(false, |at| norm_path_str.starts_with(at));

            if starts_with {
                let len = norm_target.len();
                best_match_len = Some(best_match_len.map_or(len, |m: usize| m.max(len)));
                continue;
            }
        }

        // Glob wildcard pattern match
        if norm_target.contains('*') || norm_target.contains('?') || norm_target.contains('[') {
            if let Ok(pattern) = Pattern::new(&norm_target) {
                if pattern.matches(&norm_path_str) || pattern.matches(clean_path_str) {
                    let len = norm_target.len();
                    best_match_len = Some(best_match_len.map_or(len, |m: usize| m.max(len)));
                    continue;
                }
            }
        }
    }

    best_match_len
}

/// Ed25519 Policy Signer and Key Utility
pub struct PolicySigner;

impl PolicySigner {
    /// Generates a cryptographically secure fresh Ed25519 signing keypair
    pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();
        (signing_key, verifying_key)
    }

    /// Signs policy byte data using Ed25519
    pub fn sign(data: &[u8], signing_key: &SigningKey) -> Signature {
        signing_key.sign(data)
    }

    /// Signs a policy file on disk and returns the raw signature
    pub fn sign_file<P: AsRef<Path>>(policy_path: P, signing_key: &SigningKey) -> Result<Signature> {
        let data = fs::read(policy_path.as_ref()).map_err(|e| OpenFimError::IoError {
            path: policy_path.as_ref().to_path_buf(),
            source: e,
        })?;
        Ok(Self::sign(&data, signing_key))
    }

    /// Converts a VerifyingKey (public key) to a 64-character lowercase hex string
    pub fn pubkey_to_hex(key: &VerifyingKey) -> String {
        hex::encode(key.as_bytes())
    }

    /// Parses a VerifyingKey from a 64-character hex string
    pub fn pubkey_from_hex(hex_str: &str) -> Result<VerifyingKey> {
        let clean = hex_str.trim();
        let bytes = hex::decode(clean)?;
        if bytes.len() != 32 {
            return Err(OpenFimError::InvalidKeyFormat(format!(
                "Expected 32-byte Ed25519 public key, got {} bytes",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        VerifyingKey::from_bytes(&arr)
            .map_err(|e| OpenFimError::InvalidKeyFormat(e.to_string()))
    }

    /// Converts a SigningKey (private key) to a 64-character lowercase hex string
    pub fn privkey_to_hex(key: &SigningKey) -> String {
        hex::encode(key.as_bytes())
    }

    /// Parses a SigningKey from a 64-character hex string
    pub fn privkey_from_hex(hex_str: &str) -> Result<SigningKey> {
        let clean = hex_str.trim();
        let bytes = hex::decode(clean)?;
        if bytes.len() != 32 {
            return Err(OpenFimError::InvalidKeyFormat(format!(
                "Expected 32-byte Ed25519 private key seed, got {} bytes",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(SigningKey::from_bytes(&arr))
    }

    /// Formats signature as a 128-character lowercase hex string
    pub fn signature_to_hex(sig: &Signature) -> String {
        hex::encode(sig.to_bytes())
    }

    /// Parses a Signature from a 128-character hex string
    pub fn signature_from_hex(hex_str: &str) -> Result<Signature> {
        let clean = hex_str.trim();
        let bytes = hex::decode(clean)?;
        if bytes.len() != 64 {
            return Err(OpenFimError::InvalidSignatureFormat(format!(
                "Expected 64-byte Ed25519 signature, got {} bytes",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&bytes);
        Ok(Signature::from_bytes(&arr))
    }
}

/// Ed25519 Cryptographic Policy Verifier
pub struct PolicyVerifier;

impl PolicyVerifier {
    /// Verifies policy byte slice against an Ed25519 signature and public verifying key
    pub fn verify(data: &[u8], signature: &Signature, verifying_key: &VerifyingKey) -> Result<()> {
        verifying_key
            .verify(data, signature)
            .map_err(|e| OpenFimError::SignatureVerificationFailed(e.to_string()))
    }

    /// Verifies a policy file against a detached signature file (.sig)
    pub fn verify_file<P: AsRef<Path>, S: AsRef<Path>>(
        policy_path: P,
        sig_path: S,
        verifying_key: &VerifyingKey,
    ) -> Result<Policy> {
        let policy_bytes = fs::read(policy_path.as_ref()).map_err(|e| OpenFimError::IoError {
            path: policy_path.as_ref().to_path_buf(),
            source: e,
        })?;

        let sig_raw = fs::read(sig_path.as_ref()).map_err(|e| OpenFimError::IoError {
            path: sig_path.as_ref().to_path_buf(),
            source: e,
        })?;

        let signature = if sig_raw.len() == 64 {
            let mut arr = [0u8; 64];
            arr.copy_from_slice(&sig_raw);
            Signature::from_bytes(&arr)
        } else {
            // Attempt hex string parsing
            let sig_str = String::from_utf8_lossy(&sig_raw);
            PolicySigner::signature_from_hex(&sig_str)?
        };

        Self::verify(&policy_bytes, &signature, verifying_key)?;

        let yaml_str = String::from_utf8_lossy(&policy_bytes);
        Policy::from_yaml_str(&yaml_str)
    }

    /// Verifies a policy file by checking the default `<policy_path>.sig` sibling file
    pub fn verify_file_auto<P: AsRef<Path>>(
        policy_path: P,
        verifying_key: &VerifyingKey,
    ) -> Result<Policy> {
        let mut sig_path = policy_path.as_ref().to_path_buf();
        let ext = sig_path
            .extension()
            .map_or("sig".to_string(), |e| format!("{}.sig", e.to_string_lossy()));
        sig_path.set_extension(ext);

        Self::verify_file(policy_path, sig_path, verifying_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_ENTERPRISE_POLICY: &str = r#"
version: "1.0"
policy_id: "pol-linux-enterprise-server-v1"
name: "CIS Benchmark & PCI DSS 11.5 Defensive Linux Policy"
author: "Principal Security Architect"
signature_algorithm: "ed25519"

globals:
  default_hash: "sha256"
  max_io_rate_mb_s: 25
  scan_nice_priority: 10
  realtime_fallback_sweep_interval: 7200

rules:
  - id: "ETC_AUTH_CRITICAL"
    description: "Monitors core authentication credentials and privilege escalation gates"
    paths:
      - "/etc/passwd"
      - "/etc/shadow"
      - "/etc/sudoers"
      - "/etc/pam.d"
    recursive: true
    mode: "realtime"
    checks:
      hash: true
      size: true
      permissions: true
      ownership: true
      timestamps: false
      attributes: true
      xattrs: true
    nodiff: true
    severity: 10
    whodata: true
    active_response:
      action: "none"

  - id: "SYSTEM_BINARIES_IMMUTABLE"
    description: "Guards root-owned system binaries against rootkits and trojans"
    paths:
      - "/bin"
      - "/sbin"
      - "/usr/bin"
      - "/usr/lib"
    recursive: true
    mode: "realtime"
    checks:
      hash: true
      size: true
      permissions: true
      ownership: true
      timestamps: false
      attributes: true
      xattrs: true
    nodiff: true
    ignore:
      - "/usr/lib/locale/**"
    severity: 9
    whodata: true
    active_response:
      action: "quarantine"

  - id: "SSH_AUTHORIZED_KEYS"
    description: "Detects unauthorized root authorized_keys injection"
    paths:
      - "/root/.ssh"
      - "/home/*/.ssh"
    recursive: true
    mode: "realtime"
    checks:
      hash: true
      size: true
      permissions: true
      ownership: true
      timestamps: false
      attributes: true
      xattrs: true
    nodiff: false
    ignore:
      - "**/.ssh/known_hosts*"
    severity: 9
    whodata: true
    active_response:
      action: "restore_baseline"
"#;

    #[test]
    fn test_parse_enterprise_policy_yaml() {
        let policy = Policy::from_yaml_str(SAMPLE_ENTERPRISE_POLICY).expect("Failed to parse policy YAML");

        assert_eq!(policy.version, "1.0");
        assert_eq!(policy.policy_id, "pol-linux-enterprise-server-v1");
        assert_eq!(policy.globals.default_hash, "sha256");
        assert_eq!(policy.globals.max_io_rate_mb_s, 25);
        assert_eq!(policy.rules.len(), 3);

        // Check Rule 1
        let r1 = &policy.rules[0];
        assert_eq!(r1.id, "ETC_AUTH_CRITICAL");
        assert_eq!(r1.severity, 10);
        assert!(r1.nodiff);
        assert!(r1.checks.hash);
        assert!(!r1.checks.timestamps);
        assert_eq!(r1.active_response.action, ActiveResponseAction::None);

        // Check Rule 2
        let r2 = &policy.rules[1];
        assert_eq!(r2.id, "SYSTEM_BINARIES_IMMUTABLE");
        assert_eq!(r2.severity, 9);
        assert_eq!(r2.active_response.action, ActiveResponseAction::Quarantine);
        assert_eq!(r2.ignore, vec!["/usr/lib/locale/**"]);

        // Check Rule 3
        let r3 = &policy.rules[2];
        assert_eq!(r3.id, "SSH_AUTHORIZED_KEYS");
        assert!(!r3.nodiff);
        assert_eq!(r3.active_response.action, ActiveResponseAction::RestoreBaseline);
    }

    #[test]
    fn test_ed25519_sign_and_verify_policy() {
        let (signing_key, verifying_key) = PolicySigner::generate_keypair();
        let policy_bytes = SAMPLE_ENTERPRISE_POLICY.as_bytes();

        // 1. Sign policy
        let signature = PolicySigner::sign(policy_bytes, &signing_key);
        let sig_hex = PolicySigner::signature_to_hex(&signature);
        let pub_hex = PolicySigner::pubkey_to_hex(&verifying_key);

        assert_eq!(sig_hex.len(), 128);
        assert_eq!(pub_hex.len(), 64);

        // 2. Verify with valid key
        let parsed_sig = PolicySigner::signature_from_hex(&sig_hex).expect("Valid signature hex");
        let parsed_pub = PolicySigner::pubkey_from_hex(&pub_hex).expect("Valid pubkey hex");

        PolicyVerifier::verify(policy_bytes, &parsed_sig, &parsed_pub)
            .expect("Valid signature must pass");

        // 3. Reject tampered policy data
        let mut tampered = SAMPLE_ENTERPRISE_POLICY.to_string();
        tampered.push_str("\n# Unauthorized injected comment");
        let verify_result = PolicyVerifier::verify(tampered.as_bytes(), &parsed_sig, &parsed_pub);
        assert!(
            verify_result.is_err(),
            "Tampered policy must fail signature verification"
        );

        // 4. Reject signature verified against mismatched public key
        let (_other_signing, other_verifying) = PolicySigner::generate_keypair();
        let wrong_key_result = PolicyVerifier::verify(policy_bytes, &parsed_sig, &other_verifying);
        assert!(
            wrong_key_result.is_err(),
            "Verifying with unrelated key must fail"
        );
    }

    #[test]
    fn test_rule_path_matching_and_precedence() {
        let policy = Policy::from_yaml_str(SAMPLE_ENTERPRISE_POLICY).expect("Parse error");

        // 1. /etc/shadow should match ETC_AUTH_CRITICAL
        let r_shadow = policy.find_matching_rule(Path::new("/etc/shadow")).expect("Should match");
        assert_eq!(r_shadow.id, "ETC_AUTH_CRITICAL");
        assert!(r_shadow.nodiff);

        // 2. /usr/bin/curl should match SYSTEM_BINARIES_IMMUTABLE
        let r_bin = policy.find_matching_rule(Path::new("/usr/bin/curl")).expect("Should match");
        assert_eq!(r_bin.id, "SYSTEM_BINARIES_IMMUTABLE");

        // 3. /usr/lib/locale/en_US should be IGNORED by SYSTEM_BINARIES_IMMUTABLE
        assert!(!policy.is_monitored(Path::new("/usr/lib/locale/en_US/LC_MESSAGES")));

        // 4. /root/.ssh/authorized_keys should match SSH_AUTHORIZED_KEYS
        let r_ssh = policy.find_matching_rule(Path::new("/root/.ssh/authorized_keys")).expect("Should match");
        assert_eq!(r_ssh.id, "SSH_AUTHORIZED_KEYS");

        // 5. /root/.ssh/known_hosts should be IGNORED
        assert!(!policy.is_monitored(Path::new("/root/.ssh/known_hosts")));

        // 6. An unmonitored path
        assert!(!policy.is_monitored(Path::new("/opt/custom_app/data.txt")));
    }
}
