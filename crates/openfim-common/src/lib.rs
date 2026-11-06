pub mod backup;
pub mod capabilities;
pub mod crawler;
pub mod db;
pub mod detect;
pub mod error;
pub mod fsident;
pub mod hasher;
pub mod lint;
pub mod metadata;
pub mod policy;
pub mod rate_limiter;
pub mod sweep;
pub mod whodata;

pub use backup::{
    BackupEntry, BackupManifest, BackupStore, RestoreOutcome, BACKUP_LAYOUT_VERSION, MANIFEST_FILE,
};
pub use capabilities::{
    capability_matrix, platform_name, support_for, unsupported_checks, Capability, Check, Support,
};
pub use crawler::{CrawlOptions, FileCrawler};
pub use db::{
    compute_event_hmac_for, normalize_path_str, BaselineDb, BaselineDiff, ContentChange,
    MetadataChange, SpoolAuditReport, SpoolEvent, CHAIN_GENESIS_HMAC,
};
pub use detect::{evaluate, ChangeKind, ChangeSet, SkippedCheck};
pub use ed25519_dalek;
pub use error::{OpenFimError, Result};
pub use fsident::FsIdentity;
pub use hasher::{FileIdentity, HashAlgorithm, HashResult, StreamHasher, DEFAULT_BUFFER_SIZE};
pub use hex;
pub use lint::{lint_policy, Finding, LintReport, Severity as LintSeverity};
pub use metadata::{
    ownership_checks_supported, posix_mode_supported, FileMetadata, DIRECTORY_SENTINEL_DIGEST,
};
pub use notify;
pub use policy::{
    ActiveResponseAction, ActiveResponseConfig, CompiledPolicy, Policy, PolicyGlobals, PolicyRule,
    PolicySigner, PolicyVerifier, RemediationGuard, RemediationOutcome, RuleChecks, RuleMode,
    DEFAULT_MAX_REMEDIATIONS_PER_HOUR,
};
pub use rate_limiter::TokenBucket;
pub use sweep::{
    reconcile, MissingEntry, SweepFinding, SweepOutcome, SweepReason, EVENT_HEARTBEAT,
    EVENT_SPOOL_PRUNED, EVENT_SWEEP_FOUND, EVENT_WATCH_OVERFLOW,
};
pub use whodata::ProcessContext;
