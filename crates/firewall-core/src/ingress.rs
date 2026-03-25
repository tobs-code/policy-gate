use crate::audit::sha256_hex;
use crate::pre_scan::raw_byte_pre_scan;
use crate::types::{
    AdvisoryTag, AuditEntry, BlockReason, ChannelDecision, ChannelId, ChannelResult, PromptInput,
    Verdict, VerdictKind,
};

fn synthesize_block_verdict(
    sequence: u64,
    reason: BlockReason,
    raw_hash: String,
    ingested_at_ns: u128,
    decided_at_ns: u128,
) -> Verdict {
    let block = ChannelResult {
        channel: ChannelId::A,
        decision: ChannelDecision::Block {
            reason: reason.clone(),
        },
        elapsed_us: 0,
        similarity: None,
    };
    let block_b = ChannelResult {
        channel: ChannelId::B,
        decision: ChannelDecision::Block {
            reason: reason.clone(),
        },
        elapsed_us: 0,
        similarity: None,
    };

    Verdict {
        kind: VerdictKind::Block,
        channel_a: block,
        channel_b: block_b,
        channel_d: None,
        audit: AuditEntry::basic(
            sequence,
            VerdictKind::Block,
            Some(reason),
            raw_hash,
            AdvisoryTag::None,
            None,
            None,
            None,
            None,
            ingested_at_ns,
            decided_at_ns,
            ((decided_at_ns - ingested_at_ns) / 1_000).min(u64::MAX as u128) as u64,
        ),
    }
}

pub(crate) fn pre_scan_block(
    raw: &str,
    sequence: u64,
    ingested_at_ns: u128,
    now_ns: fn() -> u128,
) -> Option<Verdict> {
    raw_byte_pre_scan(raw.as_bytes()).map(|detail| {
        let reason = BlockReason::MalformedInput { detail };
        let decided_ns = now_ns();
        synthesize_block_verdict(sequence, reason, sha256_hex(raw), ingested_at_ns, decided_ns)
    })
}

pub(crate) fn prompt_input_or_block(
    raw: String,
    sequence: u64,
    ingested_at_ns: u128,
    now_ns: fn() -> u128,
) -> Result<PromptInput, Verdict> {
    match PromptInput::new(raw.as_str()) {
        Ok(input) => Ok(input),
        Err(reason) => {
            let decided_ns = now_ns();
            Err(synthesize_block_verdict(
                sequence,
                reason,
                sha256_hex(&raw),
                ingested_at_ns,
                decided_ns,
            ))
        }
    }
}
