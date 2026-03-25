use crate::types::{AdvisoryTag, ReviewItem, ReviewStatus, Verdict, VerdictKind};

// Stores DiagnosticDisagreement and DiagnosticAgreement items requiring operator
// review. Thread-safe via Mutex.
static REVIEW_QUEUE: std::sync::Mutex<Vec<ReviewItem>> = std::sync::Mutex::new(Vec::new());

/// SLA in hours for each verdict kind.
const DIAGNOSTIC_DISAGREEMENT_SLA_HOURS: u32 = 24;
const DIAGNOSTIC_AGREEMENT_SLA_HOURS: u32 = 72;

pub(crate) fn track_review_item(verdict: &Verdict) {
    let sla_hours = match verdict.kind {
        VerdictKind::DiagnosticDisagreement => DIAGNOSTIC_DISAGREEMENT_SLA_HOURS,
        VerdictKind::DiagnosticAgreement => DIAGNOSTIC_AGREEMENT_SLA_HOURS,
        _ => return,
    };

    let advisory_score = match &verdict.audit.advisory {
        AdvisoryTag::Disagreement { score, .. } => Some(*score),
        _ => None,
    };

    let item = ReviewItem::new(
        verdict.audit.sequence,
        verdict.kind.clone(),
        verdict.audit.input_hash.clone(),
        advisory_score,
        sla_hours,
    );

    if let Ok(mut queue) = REVIEW_QUEUE.lock() {
        queue.push(item);
    }
}

pub fn get_pending_reviews() -> Vec<ReviewItem> {
    if let Ok(queue) = REVIEW_QUEUE.lock() {
        queue
            .iter()
            .filter(|r| r.status == ReviewStatus::Pending)
            .cloned()
            .collect()
    } else {
        Vec::new()
    }
}

pub fn get_expired_reviews() -> Vec<ReviewItem> {
    if let Ok(queue) = REVIEW_QUEUE.lock() {
        queue.iter().filter(|r| r.is_expired()).cloned().collect()
    } else {
        Vec::new()
    }
}

pub fn mark_reviewed(sequence: u64, reviewer: &str) -> bool {
    if let Ok(mut queue) = REVIEW_QUEUE.lock() {
        if let Some(item) = queue.iter_mut().find(|r| r.sequence == sequence) {
            if item.status == ReviewStatus::Pending {
                item.status = ReviewStatus::Reviewed {
                    reviewed_at_ns: super::now_ns(),
                    reviewer: reviewer.to_string(),
                };
                return true;
            }
        }
    }
    false
}

pub fn get_review_stats() -> ReviewStats {
    if let Ok(queue) = REVIEW_QUEUE.lock() {
        let total = queue.len();
        let pending = queue
            .iter()
            .filter(|r| r.status == ReviewStatus::Pending)
            .count();
        let expired = queue.iter().filter(|r| r.is_expired()).count();
        let reviewed = queue
            .iter()
            .filter(|r| matches!(r.status, ReviewStatus::Reviewed { .. }))
            .count();
        ReviewStats {
            total,
            pending,
            expired,
            reviewed,
        }
    } else {
        ReviewStats {
            total: 0,
            pending: 0,
            expired: 0,
            reviewed: 0,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ReviewStats {
    pub total: usize,
    pub pending: usize,
    pub expired: usize,
    pub reviewed: usize,
}
