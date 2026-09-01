//! Durable record of a person's decision to allow a guarded response.
//!
//! An approval is spent once. It names the exact run it was granted for, it
//! expires, and it cannot be replayed: consuming it is what authorises the
//! action, so a stale, duplicate or reused request finds nothing left to
//! consume rather than finding a second yes.

use crate::text::bounded_metadata;
use serde_json::{Value, json};

/// Maximum retained approval requests and decisions.
pub const MAX_APPROVAL_RECORDS: usize = 256;

/// Persisted state of one explicit local approval request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalRecordState {
    /// No person has decided and the deadline has not elapsed.
    Pending,
    /// A person explicitly allowed the requested response.
    Approved,
    /// A person explicitly denied the requested response.
    Denied,
    /// The request elapsed without a decision.
    Expired,
}

/// Bounded approval state for one exact agent identity and response scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalRecord {
    /// Stable deterministic request identifier.
    pub id: String,
    /// Target process identifier.
    pub pid: u32,
    /// Target process start time, preventing PID-reuse inheritance.
    pub started_at: u64,
    /// Sanitized rule/response scope this decision applies to.
    pub scope: String,
    /// Current explicit state.
    pub state: ApprovalRecordState,
    /// Creation time in epoch milliseconds.
    pub created_at: u64,
    /// Fail-closed deadline in epoch milliseconds.
    pub expires_at: u64,
    /// Resolution time for approved, denied, or expired records.
    pub resolved_at: Option<u64>,
}

pub(crate) fn approval_id(pid: u32, started_at: u64, scope: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut scope_hex = String::with_capacity(scope.len().saturating_mul(2));
    for byte in scope.as_bytes() {
        scope_hex.push(char::from(
            HEX.get(usize::from(*byte >> 4)).copied().unwrap_or(b'0'),
        ));
        scope_hex.push(char::from(
            HEX.get(usize::from(*byte & 0x0f)).copied().unwrap_or(b'0'),
        ));
    }
    format!("approval-{pid}-{started_at}-{scope_hex}")
}

pub(crate) fn approval_record_json(record: &ApprovalRecord) -> Value {
    json!({
        "id": record.id,
        "pid": record.pid,
        "started_at": record.started_at,
        "scope": record.scope,
        "state": record.state.as_str(),
        "created_at": record.created_at,
        "expires_at": record.expires_at,
        "resolved_at": record.resolved_at,
    })
}

pub(crate) fn approval_record_from_json(value: &Value) -> Option<ApprovalRecord> {
    let pid = u32::try_from(value.get("pid")?.as_u64()?).ok()?;
    let started_at = value.get("started_at")?.as_u64()?;
    let scope = value.get("scope")?.as_str()?.to_owned();
    if scope.is_empty() || scope.chars().count() > 256 || bounded_metadata(&scope, 256) != scope {
        return None;
    }
    let id = value.get("id")?.as_str()?.to_owned();
    if id != approval_id(pid, started_at, &scope) {
        return None;
    }
    let state = match value.get("state")?.as_str()? {
        "pending" => ApprovalRecordState::Pending,
        "approved" => ApprovalRecordState::Approved,
        "denied" => ApprovalRecordState::Denied,
        "expired" => ApprovalRecordState::Expired,
        _ => return None,
    };
    let created_at = value.get("created_at")?.as_u64()?;
    let expires_at = value.get("expires_at")?.as_u64()?;
    if expires_at <= created_at {
        return None;
    }
    let resolved_at = value.get("resolved_at").and_then(Value::as_u64);
    let valid_resolution = match state {
        ApprovalRecordState::Pending => resolved_at.is_none(),
        ApprovalRecordState::Approved | ApprovalRecordState::Denied => {
            resolved_at.is_some_and(|at| at >= created_at && at <= expires_at)
        }
        ApprovalRecordState::Expired => resolved_at == Some(expires_at),
    };
    valid_resolution.then_some(ApprovalRecord {
        id,
        pid,
        started_at,
        scope,
        state,
        created_at,
        expires_at,
        resolved_at,
    })
}

impl ApprovalRecordState {
    /// Stable persistence and report label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Denied => "denied",
            Self::Expired => "expired",
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use crate::journal::Journal;
    use crate::test_support::test_dir;
    use crate::{ApprovalRecordState, MAX_APPROVAL_RECORDS};

    #[test]
    fn approval_requests_are_idempotent_exact_identity_safe_and_fail_closed() -> std::io::Result<()>
    {
        let dir = test_dir("approval");
        let journal = Journal::at(&dir);
        let first = journal.request_approval(42, 1_000, "watchlist:0:kill", 2_000, 500)?;
        let duplicate = journal.request_approval(42, 1_000, "watchlist:0:kill", 2_100, 500)?;
        assert_eq!(first, duplicate);
        assert_eq!(journal.approval_records(2_100)?.len(), 1);
        assert!(
            journal
                .resolve_approval(&first.id, 42, 999, ApprovalRecordState::Approved, 2_200)?
                .is_none()
        );
        let approved = journal
            .resolve_approval(&first.id, 42, 1_000, ApprovalRecordState::Approved, 2_200)?
            .ok_or_else(|| std::io::Error::other("exact pending request did not resolve"))?;
        assert_eq!(approved.state, ApprovalRecordState::Approved);
        assert_eq!(approved.resolved_at, Some(2_200));
        assert!(
            journal
                .resolve_approval(&first.id, 42, 1_000, ApprovalRecordState::Denied, 2_300)?
                .is_none(),
            "a resolved request cannot be replayed"
        );

        let elapsed = journal.request_approval(43, 3_000, "watchlist:1:kill", 4_000, 100)?;
        let records = journal.approval_records(4_100)?;
        assert!(records.iter().any(|record| {
            record.id == elapsed.id
                && record.state == ApprovalRecordState::Expired
                && record.resolved_at == Some(4_100)
        }));
        assert!(
            journal
                .resolve_approval(&elapsed.id, 43, 3_000, ApprovalRecordState::Approved, 4_100)?
                .is_none()
        );
        let _ = std::fs::remove_dir_all(dir);
        Ok(())
    }

    #[test]
    fn approval_retention_is_bounded_and_malformed_members_are_skipped() -> std::io::Result<()> {
        let dir = test_dir("approval-bound");
        let journal = Journal::at(&dir);
        for index in 0..=MAX_APPROVAL_RECORDS {
            journal.request_approval(
                42,
                1_000,
                &format!("watchlist:{index}:kill"),
                2_000 + u64::try_from(index).unwrap_or(u64::MAX),
                10_000,
            )?;
        }
        let records = journal.approval_records(3_000)?;
        assert_eq!(records.len(), MAX_APPROVAL_RECORDS);
        assert!(
            !records
                .iter()
                .any(|record| record.scope == "watchlist:0:kill")
        );
        std::fs::write(journal.approval_path(), r#"[{"id":"forged"}]"#)?;
        assert!(journal.approval_records(3_000)?.is_empty());
        let _ = std::fs::remove_dir_all(dir);
        Ok(())
    }
}
