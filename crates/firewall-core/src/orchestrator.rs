use crate::advisory;
use crate::config;
use crate::fsm::ChannelA;
use crate::init::{active_profile_intents, get_config};
use crate::rule_engine::ChannelB;
use crate::types::{
    AuditDetailLevel, BlockReason, ChannelDecision, PromptInput, Verdict, VerdictKind,
};
use crate::verdict_build::{advisory_tag as build_advisory_tag, build_final_verdict};
use crate::voter::Voter;

fn apply_profile_filter(
    verdict_kind: &mut VerdictKind,
    channel_a: &mut crate::ChannelResult,
    channel_b: &mut crate::ChannelResult,
) {
    if !matches!(
        verdict_kind,
        VerdictKind::Pass | VerdictKind::DiagnosticAgreement
    ) {
        return;
    }

    if let Some(permitted) = active_profile_intents() {
        let matched_intent = match &channel_a.decision {
            ChannelDecision::Pass { intent } => Some(intent),
            _ => match &channel_b.decision {
                ChannelDecision::Pass { intent } => Some(intent),
                _ => None,
            },
        };

        if let Some(intent) = matched_intent {
            if !permitted.contains(intent) {
                *verdict_kind = VerdictKind::Block;
                let reason = BlockReason::ProhibitedIntent {
                    intent: intent.clone(),
                };
                channel_a.decision = ChannelDecision::Block {
                    reason: reason.clone(),
                };
                channel_b.decision = ChannelDecision::Block { reason };
            }
        }
    }
}

fn audit_detail_level() -> AuditDetailLevel {
    get_config()
        .and_then(|c: &config::FirewallConfig| c.audit_detail_level)
        .unwrap_or(AuditDetailLevel::Basic)
}

pub(crate) fn evaluate(
    input: PromptInput,
    sequence: u64,
    now_ns: fn() -> u128,
) -> Verdict {
    let start_ns = now_ns();

    let mut channel_a = ChannelA::evaluate(&input);
    let mut channel_b = ChannelB::evaluate(&input);

    #[cfg(feature = "semantic")]
    let channel_d = crate::semantic::ChannelD::evaluate(&input.text);
    #[cfg(feature = "semantic")]
    let semantic_similarity = channel_d.similarity;
    #[cfg(not(feature = "semantic"))]
    let _semantic_similarity: Option<f32> = None;

    let mut verdict_kind = Voter::decide(&channel_a, &channel_b);
    apply_profile_filter(&mut verdict_kind, &mut channel_a, &mut channel_b);

    let advisory_opinion = advisory::ChannelC::evaluate(&input.text);
    let advisory_event = advisory::ChannelC::audit_event(&advisory_opinion, &verdict_kind);
    let advisory_tag = build_advisory_tag(&advisory_event);

    let decided_ns = now_ns();
    let total_us = ((decided_ns - start_ns) / 1_000).min(u64::MAX as u128) as u64;

    build_final_verdict(
        &input,
        sequence,
        verdict_kind,
        advisory_tag,
        decided_ns,
        total_us,
        channel_a,
        channel_b,
        #[cfg(feature = "semantic")]
        channel_d,
        #[cfg(feature = "semantic")]
        semantic_similarity,
        #[cfg(not(feature = "semantic"))]
        None,
        audit_detail_level(),
    )
}
