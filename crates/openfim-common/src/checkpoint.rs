//! Signed chain checkpoints: making the audit log survive host compromise.
//!
//! # What the HMAC chain does and does not prove
//!
//! The event spool is chained with HMAC-SHA256, which proves that no event was *edited*
//! and that none was deleted from the middle or the end — as long as the verifier does
//! not also hold the signing key.
//!
//! But the agent must have that key to append events, so on a compromised host the
//! attacker has it too. With the key they can discard the spool and rebuild a clean,
//! internally consistent chain from scratch. Verification then passes. The chain's
//! guarantee is therefore conditional on the host not being root-compromised, which is
//! exactly the scenario a file integrity monitor exists to detect.
//!
//! # What a checkpoint adds
//!
//! A checkpoint is a small record of where the chain head was at a point in time:
//!
//! ```text
//!   sequence_id, event_count, chain head HMAC, timestamp
//! ```
//!
//! signed with the **Ed25519 administrative key** — the same key that signs policies,
//! whose private half lives offline and is never on the monitored host. The agent holds
//! only the public key, so it can *verify* checkpoints but cannot forge one.
//!
//! Checkpoints are appended to a separate file intended to be shipped off-host. An
//! attacker who rewrites the spool cannot produce a checkpoint matching their forged
//! chain, so the forgery is detectable by comparing the two.
//!
//! # The honest limit
//!
//! This does not prevent tampering, and it does not protect events recorded *after* the
//! compromise. It makes wholesale replacement of the log **detectable**, which is a
//! strictly weaker and much more achievable property. Full protection needs the private
//! key to sign on the host, which would put it on the host — so the real answer is
//! hardware-backed signing (TPM 2.0 sealing, roadmap Phase 3).

use std::path::Path;

use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::db::BaselineDb;
use crate::error::{OpenFimError, Result};
use crate::policy::{PolicySigner, PolicyVerifier};

/// Domain tag, so a checkpoint signature can never be replayed as a policy signature.
const CHECKPOINT_DOMAIN: &str = "openfim.chain-checkpoint.v1";

/// One signed observation of the chain head.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    /// Domain separation tag; rejected if it does not match.
    pub domain: String,
    /// Highest sequence id in the spool when this checkpoint was taken.
    pub last_sequence_id: i64,
    /// Number of events in the spool at that moment.
    pub event_count: i64,
    /// The chain head HMAC at that moment.
    pub last_hmac: String,
    /// Unix seconds when the checkpoint was taken.
    pub taken_at: i64,
    /// Optional host identifier, so checkpoints from a fleet can be told apart.
    #[serde(default)]
    pub host: Option<String>,
    /// Ed25519 signature over the canonical encoding, hex-encoded.
    pub signature: String,
}

impl Checkpoint {
    /// The exact bytes that are signed.
    ///
    /// Built field by field with length prefixes rather than by serializing the struct,
    /// so the signed form cannot shift if the JSON representation ever changes field
    /// order or formatting.
    fn signing_payload(
        last_sequence_id: i64,
        event_count: i64,
        last_hmac: &str,
        taken_at: i64,
        host: Option<&str>,
    ) -> Vec<u8> {
        let mut buf = Vec::new();

        let mut field = |bytes: &[u8]| {
            buf.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
            buf.extend_from_slice(bytes);
        };

        field(CHECKPOINT_DOMAIN.as_bytes());
        field(&last_sequence_id.to_le_bytes());
        field(&event_count.to_le_bytes());
        field(last_hmac.as_bytes());
        field(&taken_at.to_le_bytes());
        field(host.unwrap_or("").as_bytes());

        buf
    }

    /// Verifies this checkpoint's signature against the administrative public key.
    pub fn verify_signature(&self, verifying_key: &VerifyingKey) -> Result<()> {
        if self.domain != CHECKPOINT_DOMAIN {
            return Err(OpenFimError::SignatureVerificationFailed(format!(
                "checkpoint has domain {:?}, expected {:?}",
                self.domain, CHECKPOINT_DOMAIN
            )));
        }
        let payload = Self::signing_payload(
            self.last_sequence_id,
            self.event_count,
            &self.last_hmac,
            self.taken_at,
            self.host.as_deref(),
        );
        let signature = PolicySigner::signature_from_hex(&self.signature)?;
        PolicyVerifier::verify(&payload, &signature, verifying_key)
    }
}

/// Captures the current chain head and signs it.
///
/// Requires the **private** administrative key, so this is an offline or
/// administrative operation, not something the monitored host does for itself. An agent
/// able to mint its own checkpoints would give an attacker the same ability.
pub fn create(db: &BaselineDb, signing_key: &SigningKey, host: Option<&str>) -> Result<Checkpoint> {
    let (last_sequence_id, last_hmac, event_count) = db.observed_chain_head()?;
    let taken_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let payload =
        Checkpoint::signing_payload(last_sequence_id, event_count, &last_hmac, taken_at, host);
    let signature = PolicySigner::sign(&payload, signing_key);

    Ok(Checkpoint {
        domain: CHECKPOINT_DOMAIN.to_string(),
        last_sequence_id,
        event_count,
        last_hmac,
        taken_at,
        host: host.map(str::to_string),
        signature: PolicySigner::signature_to_hex(&signature),
    })
}

/// Appends a checkpoint to a newline-delimited JSON ledger.
///
/// Append-only and line-oriented on purpose: the file is meant to be shipped off-host
/// (to a syslog collector, an object store, a printer), and a format that only ever
/// grows at the end is trivial to tail and to replicate.
pub fn append_to_ledger(path: &Path, checkpoint: &Checkpoint) -> Result<()> {
    use std::io::Write;

    let line = serde_json::to_string(checkpoint)?;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| OpenFimError::IoError {
            path: path.to_path_buf(),
            source: e,
        })?;
    writeln!(file, "{}", line).map_err(|e| OpenFimError::IoError {
        path: path.to_path_buf(),
        source: e,
    })?;
    file.sync_all().map_err(|e| OpenFimError::IoError {
        path: path.to_path_buf(),
        source: e,
    })?;
    Ok(())
}

/// Reads every checkpoint from a ledger, newest last.
///
/// A malformed line is an error rather than something to skip: silently ignoring
/// unparseable checkpoints would let an attacker disable the comparison by corrupting
/// the file instead of rewriting it.
pub fn read_ledger(path: &Path) -> Result<Vec<Checkpoint>> {
    let text = std::fs::read_to_string(path).map_err(|e| OpenFimError::IoError {
        path: path.to_path_buf(),
        source: e,
    })?;

    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let cp: Checkpoint = serde_json::from_str(line).map_err(|e| {
            OpenFimError::Other(format!(
                "checkpoint ledger {} line {} is malformed: {}",
                path.display(),
                n + 1,
                e
            ))
        })?;
        out.push(cp);
    }
    Ok(out)
}

/// What a checkpoint comparison concluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckpointVerdict {
    /// The chain is consistent with every signed checkpoint.
    Consistent { checkpoints_verified: usize },
    /// The chain is shorter than a checkpoint recorded, so events were destroyed.
    EvidenceDestroyed {
        expected_count: i64,
        actual_count: i64,
        expected_sequence: i64,
    },
    /// The chain reached the checkpointed length but with a different head, so the log
    /// was rewritten rather than merely truncated.
    ChainRewritten {
        at_sequence: i64,
        expected_hmac: String,
        actual_hmac: String,
    },
    /// A checkpoint's signature did not verify.
    ForgedCheckpoint { reason: String },
    /// No checkpoints exist to compare against.
    NoCheckpoints,
}

impl CheckpointVerdict {
    /// True only when the chain is provably consistent with the signed record.
    pub fn is_consistent(&self) -> bool {
        matches!(self, CheckpointVerdict::Consistent { .. })
    }

    /// Operator-facing explanation.
    pub fn explain(&self) -> String {
        match self {
            CheckpointVerdict::Consistent {
                checkpoints_verified,
            } => format!(
                "chain is consistent with {} signed checkpoint(s)",
                checkpoints_verified
            ),
            CheckpointVerdict::EvidenceDestroyed {
                expected_count,
                actual_count,
                expected_sequence,
            } => format!(
                "EVIDENCE DESTROYED: a signed checkpoint records {} event(s) up to sequence {}, \
                 but the spool now holds only {}. Events were deleted, and the deletion was \
                 not performed by anything holding the administrative key.",
                expected_count, expected_sequence, actual_count
            ),
            CheckpointVerdict::ChainRewritten {
                at_sequence,
                expected_hmac,
                actual_hmac,
            } => format!(
                "CHAIN REWRITTEN: at sequence {} a signed checkpoint records head {}, but the \
                 spool reports {}. The log was replaced with a forged but internally \
                 consistent one.",
                at_sequence,
                &expected_hmac[..expected_hmac.len().min(16)],
                &actual_hmac[..actual_hmac.len().min(16)]
            ),
            CheckpointVerdict::ForgedCheckpoint { reason } => format!(
                "FORGED CHECKPOINT: a checkpoint in the ledger is not signed by the \
                 administrative key ({}). Either the ledger was tampered with, or it \
                 belongs to a different deployment.",
                reason
            ),
            CheckpointVerdict::NoCheckpoints => {
                "no checkpoints available, so wholesale replacement of the log cannot be \
                 ruled out"
                    .to_string()
            }
        }
    }
}

/// Compares the live chain against a ledger of signed checkpoints.
///
/// This is the check the HMAC chain cannot perform on its own, because the agent holds
/// the HMAC key and an attacker on the host holds it too.
pub fn verify_against_ledger(
    db: &BaselineDb,
    checkpoints: &[Checkpoint],
    verifying_key: &VerifyingKey,
) -> Result<CheckpointVerdict> {
    if checkpoints.is_empty() {
        return Ok(CheckpointVerdict::NoCheckpoints);
    }

    // Every checkpoint's signature is verified before any of them is trusted as
    // evidence. An unsigned or wrongly-signed checkpoint is itself a finding.
    for cp in checkpoints {
        if let Err(e) = cp.verify_signature(verifying_key) {
            return Ok(CheckpointVerdict::ForgedCheckpoint {
                reason: e.to_string(),
            });
        }
    }

    let (live_sequence, live_hmac, live_count) = db.observed_chain_head()?;

    // The most advanced checkpoint is the strongest claim about what must still exist.
    let newest = checkpoints
        .iter()
        .max_by_key(|c| (c.event_count, c.last_sequence_id))
        .expect("non-empty");

    if live_count < newest.event_count || live_sequence < newest.last_sequence_id {
        return Ok(CheckpointVerdict::EvidenceDestroyed {
            expected_count: newest.event_count,
            actual_count: live_count,
            expected_sequence: newest.last_sequence_id,
        });
    }

    // Same length, different head: the log was rebuilt rather than extended.
    if live_count == newest.event_count && live_hmac != newest.last_hmac {
        return Ok(CheckpointVerdict::ChainRewritten {
            at_sequence: newest.last_sequence_id,
            expected_hmac: newest.last_hmac.clone(),
            actual_hmac: live_hmac,
        });
    }

    Ok(CheckpointVerdict::Consistent {
        checkpoints_verified: checkpoints.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::SpoolEvent;
    use tempfile::tempdir;

    const KEY: &[u8] = b"checkpoint-test-hmac-key";

    fn event(id: &str) -> SpoolEvent {
        SpoolEvent {
            sequence_id: None,
            event_id: id.to_string(),
            timestamp_nano: 1,
            event_type: "CONTENT_MUTATED".to_string(),
            path: format!("/etc/{}", id),
            severity: 9,
            whodata_pid: None,
            whodata_uid: None,
            whodata_comm: None,
            whodata_exe: None,
            whodata_cmdline: None,
            whodata_cgroup: None,
            old_sha256: None,
            new_sha256: None,
            diff_snippet: None,
            hmac_signature: String::new(),
            sent_to_manager: false,
        }
    }

    fn seeded(n: usize) -> BaselineDb {
        let db = BaselineDb::open_in_memory().unwrap();
        for i in 0..n {
            let mut ev = event(&format!("evt-{}", i));
            db.append_spool_event_chained(&mut ev, KEY).unwrap();
        }
        db
    }

    #[test]
    fn a_fresh_checkpoint_is_consistent() {
        let db = seeded(5);
        let (sk, vk) = PolicySigner::generate_keypair();
        let cp = create(&db, &sk, Some("host-a")).unwrap();

        let verdict = verify_against_ledger(&db, &[cp], &vk).unwrap();
        assert!(verdict.is_consistent(), "{}", verdict.explain());
    }

    #[test]
    fn appending_more_events_stays_consistent() {
        // A checkpoint is a floor, not an exact match: the chain is expected to grow.
        let db = seeded(5);
        let (sk, vk) = PolicySigner::generate_keypair();
        let cp = create(&db, &sk, None).unwrap();

        let mut ev = event("evt-later");
        db.append_spool_event_chained(&mut ev, KEY).unwrap();

        assert!(verify_against_ledger(&db, &[cp], &vk)
            .unwrap()
            .is_consistent());
    }

    #[test]
    fn deleting_the_whole_log_is_detected() {
        // The attack the HMAC chain alone cannot catch: with the HMAC key in hand, an
        // attacker wipes the spool and starts a fresh, internally valid chain.
        let db = seeded(6);
        let (sk, vk) = PolicySigner::generate_keypair();
        let cp = create(&db, &sk, None).unwrap();

        db.connection()
            .execute("DELETE FROM event_spool", [])
            .unwrap();
        db.connection()
            .execute("DELETE FROM chain_meta", [])
            .unwrap();

        let verdict = verify_against_ledger(&db, &[cp], &vk).unwrap();
        assert!(
            !verdict.is_consistent(),
            "wiping the log verified as consistent"
        );
        assert!(
            matches!(verdict, CheckpointVerdict::EvidenceDestroyed { .. }),
            "{}",
            verdict.explain()
        );
        assert!(verdict.explain().contains("EVIDENCE DESTROYED"));
    }

    #[test]
    fn truncating_the_tail_is_detected() {
        let db = seeded(6);
        let (sk, vk) = PolicySigner::generate_keypair();
        let cp = create(&db, &sk, None).unwrap();

        db.connection()
            .execute("DELETE FROM event_spool WHERE sequence_id >= 5", [])
            .unwrap();

        let verdict = verify_against_ledger(&db, &[cp], &vk).unwrap();
        assert!(matches!(
            verdict,
            CheckpointVerdict::EvidenceDestroyed { .. }
        ));
    }

    #[test]
    fn rebuilding_the_chain_to_the_same_length_is_detected() {
        // Same event count, different head: the log was replaced, not shortened.
        let db = seeded(4);
        let (sk, vk) = PolicySigner::generate_keypair();
        let cp = create(&db, &sk, None).unwrap();

        // Forge a chain of the same length with different content.
        db.connection()
            .execute("DELETE FROM event_spool", [])
            .unwrap();
        db.connection()
            .execute("DELETE FROM chain_meta", [])
            .unwrap();
        for i in 0..4 {
            let mut ev = event(&format!("forged-{}", i));
            db.append_spool_event_chained(&mut ev, KEY).unwrap();
        }

        let verdict = verify_against_ledger(&db, &[cp], &vk).unwrap();
        assert!(
            !verdict.is_consistent(),
            "a rebuilt chain of equal length verified as consistent"
        );
        assert!(
            matches!(verdict, CheckpointVerdict::ChainRewritten { .. }),
            "{}",
            verdict.explain()
        );
    }

    #[test]
    fn a_checkpoint_signed_by_the_wrong_key_is_rejected() {
        let db = seeded(3);
        let (attacker_sk, _) = PolicySigner::generate_keypair();
        let (_, admin_vk) = PolicySigner::generate_keypair();

        // The attacker mints their own checkpoint matching their forged chain.
        let forged = create(&db, &attacker_sk, None).unwrap();

        let verdict = verify_against_ledger(&db, &[forged], &admin_vk).unwrap();
        assert!(
            matches!(verdict, CheckpointVerdict::ForgedCheckpoint { .. }),
            "a checkpoint signed by an unknown key was accepted: {}",
            verdict.explain()
        );
    }

    #[test]
    fn tampering_with_a_checkpoint_field_breaks_its_signature() {
        let db = seeded(5);
        let (sk, vk) = PolicySigner::generate_keypair();
        let mut cp = create(&db, &sk, None).unwrap();

        // Lower the recorded count so a truncated chain would appear consistent.
        cp.event_count = 1;

        assert!(cp.verify_signature(&vk).is_err());
        assert!(matches!(
            verify_against_ledger(&db, &[cp], &vk).unwrap(),
            CheckpointVerdict::ForgedCheckpoint { .. }
        ));
    }

    #[test]
    fn every_signed_field_is_covered() {
        let db = seeded(3);
        let (sk, vk) = PolicySigner::generate_keypair();
        let base = create(&db, &sk, Some("host-a")).unwrap();

        /// One named mutation of a checkpoint, used to prove each field is signed.
        type Mutation = (&'static str, Box<dyn Fn(&mut Checkpoint)>);

        let mutations: Vec<Mutation> = vec![
            (
                "last_sequence_id",
                Box::new(|c: &mut Checkpoint| c.last_sequence_id = 99),
            ),
            (
                "event_count",
                Box::new(|c: &mut Checkpoint| c.event_count = 99),
            ),
            (
                "last_hmac",
                Box::new(|c: &mut Checkpoint| c.last_hmac = "f".repeat(64)),
            ),
            ("taken_at", Box::new(|c: &mut Checkpoint| c.taken_at = 1)),
            (
                "host",
                Box::new(|c: &mut Checkpoint| c.host = Some("other".into())),
            ),
            (
                "domain",
                Box::new(|c: &mut Checkpoint| c.domain = "other".into()),
            ),
        ];

        for (field, mutate) in mutations {
            let mut cp = base.clone();
            mutate(&mut cp);
            assert!(
                cp.verify_signature(&vk).is_err(),
                "tampering with `{}` did not break the signature, so the field is \
                 outside the signed payload",
                field
            );
        }
    }

    #[test]
    fn no_checkpoints_is_reported_not_treated_as_clean() {
        let db = seeded(3);
        let (_, vk) = PolicySigner::generate_keypair();
        let verdict = verify_against_ledger(&db, &[], &vk).unwrap();
        assert_eq!(verdict, CheckpointVerdict::NoCheckpoints);
        assert!(
            !verdict.is_consistent(),
            "absent checkpoints must not count as a consistent chain"
        );
    }

    #[test]
    fn ledger_round_trips_through_disk() {
        let dir = tempdir().unwrap();
        let ledger = dir.path().join("checkpoints.jsonl");
        let db = seeded(4);
        let (sk, vk) = PolicySigner::generate_keypair();

        let cp1 = create(&db, &sk, Some("host-a")).unwrap();
        append_to_ledger(&ledger, &cp1).unwrap();

        let mut ev = event("evt-extra");
        db.append_spool_event_chained(&mut ev, KEY).unwrap();
        let cp2 = create(&db, &sk, Some("host-a")).unwrap();
        append_to_ledger(&ledger, &cp2).unwrap();

        let read = read_ledger(&ledger).unwrap();
        assert_eq!(read.len(), 2);
        assert_eq!(read[0], cp1);
        assert_eq!(read[1], cp2);
        assert!(verify_against_ledger(&db, &read, &vk)
            .unwrap()
            .is_consistent());
    }

    #[test]
    fn a_malformed_ledger_line_is_an_error_not_a_skip() {
        // Silently skipping unparseable lines would let an attacker disable the
        // comparison by corrupting the ledger instead of rewriting the spool.
        let dir = tempdir().unwrap();
        let ledger = dir.path().join("checkpoints.jsonl");
        std::fs::write(&ledger, "{\"not\": \"a checkpoint\"}\n").unwrap();

        let err = read_ledger(&ledger).expect_err("a malformed ledger must be an error");
        assert!(err.to_string().contains("malformed"));
    }

    #[test]
    fn the_newest_checkpoint_governs() {
        // An attacker who keeps an old checkpoint and deletes newer ones must still be
        // caught by whichever is the most advanced claim available.
        let db = seeded(3);
        let (sk, vk) = PolicySigner::generate_keypair();
        let early = create(&db, &sk, None).unwrap();

        for i in 0..5 {
            let mut ev = event(&format!("later-{}", i));
            db.append_spool_event_chained(&mut ev, KEY).unwrap();
        }
        let late = create(&db, &sk, None).unwrap();

        // Truncate back to the early checkpoint's length.
        db.connection()
            .execute("DELETE FROM event_spool WHERE sequence_id > 3", [])
            .unwrap();

        // With only the early checkpoint this looks fine...
        assert!(
            verify_against_ledger(&db, std::slice::from_ref(&early), &vk)
                .unwrap()
                .is_consistent()
        );
        // ...but the later one catches it.
        assert!(!verify_against_ledger(&db, &[early, late], &vk)
            .unwrap()
            .is_consistent());
    }
}
