// firewall-napi/src/lib.rs — napi-rs binding for Node.js
//
// This layer is NOT part of the safety function.
// It marshals data between JS and the Rust core.
//
// OC-01 enforcement: firewall_evaluate() checks INIT_RESULT before every
// evaluation. If init() was never called or failed, the call is rejected
// with a Block verdict — the safety function never runs in an uninitialised
// state. This closes the caller-contract gap identified in SA-021.

#![deny(clippy::all)]

use firewall_core::{evaluate_messages, evaluate_output, evaluate_raw, init, ChatMessage, PromptInput};
use napi::bindgen_prelude::*;
use napi_derive::napi;
use std::sync::OnceLock;

// ─── Init guard (SA-021) ──────────────────────────────────────────────────────
//
// Stores the result of the first init() call. Subsequent calls to
// firewall_evaluate() check this before running any channel evaluation.
//
// OnceLock guarantees: initialised at most once, visible to all threads
// after the first write (sequentially consistent via the OnceLock contract).
//
// Failure mode: if INIT_RESULT is Err, firewall_evaluate returns
// Err(napi::Error) — the JS caller receives a rejected Promise and must
// not forward the input to the LLM. This is fail-closed at the binding layer.
static INIT_RESULT: OnceLock<std::result::Result<(), String>> = OnceLock::new();

/// Call once at startup before any evaluate() calls.
/// Returns null on success, error string on failure.
/// If this returns an error the process must not call firewall_evaluate().
#[napi]
pub fn firewall_init() -> Option<String> {
    let result: &std::result::Result<(), String> = INIT_RESULT.get_or_init(|| {
        init().map_err(|e: firewall_core::FirewallInitError| e.to_string())
    });
    match result {
        Ok(()) => None,
        Err(e) => Some(e.clone()),
    }
}

#[napi(object)]
pub struct JsEvalInput {
    pub text: String,
    pub role: Option<String>,
    pub sequence: u32,
}

#[napi(object)]
pub struct JsVerdict {
    pub kind: String,
    pub is_pass: bool,
    pub channel_a_decision: String,
    pub channel_b_decision: String,
    pub elapsed_us: u32,
    pub input_hash: String,
    pub sequence: u32,
    /// Populated for all Block verdicts. Empty string on Pass.
    pub block_reason: String,
}

#[napi]
pub async fn firewall_evaluate(input: JsEvalInput) -> Result<JsVerdict> {
    // OC-01 guard (SA-021): reject evaluation if init() was never called or failed.
    // get_or_init here ensures that even if firewall_init() was never called,
    // we attempt init() exactly once and cache the result.
    let init_ok: &std::result::Result<(), String> = INIT_RESULT.get_or_init(|| {
        init().map_err(|e: firewall_core::FirewallInitError| e.to_string())
    });
    if let Err(e) = init_ok {
        return Err(napi::Error::from_reason(format!(
            "firewall not initialised (OC-01): {}. Call firewall_init() at startup and check its result.",
            e
        )));
    }

    let text = input.text;
    let sequence = input.sequence as u64;
    // Note: input.role is metadata only — not used in any safety-path evaluation.
    // evaluate_raw handles normalisation, size-check, and both channels internally.

    // SA-010: PromptInput::new hard-rejects oversized inputs.
    // SA-034: Use evaluate_raw as the single entry point — avoids double
    // normalisation (PromptInput::new called here AND inside evaluate_raw)
    // and keeps the oversized-input path consistent with the core API contract.
    // The init guard above already confirmed is_initialised() == true, so
    // evaluate_raw's internal guard is a no-op (not a double-check concern).
    let verdict = evaluate_raw(text, sequence);

    let block_reason = verdict.audit.block_reason
        .as_ref()
        .map(stable_block_reason)
        .unwrap_or_default();

    Ok(JsVerdict {
        kind: stable_verdict_kind(&verdict.kind),
        is_pass: verdict.is_pass(),
        channel_a_decision: stable_channel_decision(&verdict.channel_a.decision),
        channel_b_decision: stable_channel_decision(&verdict.channel_b.decision),
        elapsed_us: verdict.audit.total_elapsed_us.min(u32::MAX as u64) as u32,
        input_hash: verdict.audit.input_hash,
        sequence: verdict.audit.sequence.min(u32::MAX as u64) as u32,
        block_reason,
    })
}

// ─── Stable serialisation helpers ────────────────────────────────────────────
//
// Using Debug format for public API fields is fragile — enum variant names can
// change without a semver bump and break JS-side parsing silently.
// These helpers produce stable, documented string values.

fn stable_verdict_kind(k: &firewall_core::VerdictKind) -> String {
    use firewall_core::VerdictKind::*;
    match k {
        Pass                  => "Pass".into(),
        Block                 => "Block".into(),
        DiagnosticAgreement   => "DiagnosticAgreement".into(),
        DiagnosticDisagreement => "DiagnosticDisagreement".into(),
        EgressBlock           => "EgressBlock".into(),
    }
}

fn stable_block_reason(r: &firewall_core::BlockReason) -> String {
    use firewall_core::BlockReason::*;
    match r {
        NoIntentMatch              => "NoIntentMatch".into(),
        ExceededMaxLength          => "ExceededMaxLength".into(),
        WatchdogTimeout            => "WatchdogTimeout".into(),
        ForbiddenPattern { pattern_id } => format!("ForbiddenPattern:{}", pattern_id),
        MalformedInput   { detail }     => format!("MalformedInput:{}", detail),
        ProhibitedIntent { intent }     => format!("ProhibitedIntent:{}", stable_intent(intent)),
        SemanticTrigger { similarity, reason } => format!("SemanticTrigger:{:.3}:{}", similarity, reason),
    }
}

fn stable_channel_decision(d: &firewall_core::ChannelDecision) -> String {
    use firewall_core::ChannelDecision::*;
    match d {
        Pass { intent } => format!("Pass:{}", stable_intent(intent)),
        Block { reason } => format!("Block:{}", stable_block_reason(reason)),
        Fault { code }   => format!("Fault:{}", stable_fault_code(code)),
    }
}

fn stable_intent(i: &firewall_core::MatchedIntent) -> &'static str {
    use firewall_core::MatchedIntent::*;
    match i {
        QuestionFactual              => "QuestionFactual",
        QuestionCausal               => "QuestionCausal",
        QuestionComparative          => "QuestionComparative",
        TaskCodeGeneration           => "TaskCodeGeneration",
        TaskTextSummarisation        => "TaskTextSummarisation",
        TaskTranslation              => "TaskTranslation",
        TaskDataExtraction           => "TaskDataExtraction",
        ConversationalGreeting       => "ConversationalGreeting",
        ConversationalAcknowledgement => "ConversationalAcknowledgement",
        SystemMetaQuery              => "SystemMetaQuery",
        StructuredOutput             => "StructuredOutput",
        AgenticToolUse               => "AgenticToolUse",
        ControlledCreative           => "ControlledCreative",
        SemanticViolation { .. }     => "SemanticViolation",
    }
}

fn stable_fault_code(c: &firewall_core::FaultCode) -> &'static str {
    use firewall_core::FaultCode::*;
    match c {
        WatchdogFired            => "WatchdogFired",
        InternalPanic            => "InternalPanic",
        RegexCompilationFailure  => "RegexCompilationFailure",
    }
}

// ─── Multi-message API ────────────────────────────────────────────────────────

#[napi(object)]
pub struct JsChatMessage {
    pub role: String,
    pub content: String,
}

#[napi(object)]
pub struct JsConversationVerdict {
    pub is_pass: bool,
    /// -1 if no message was blocked, otherwise the 0-based index of the first block.
    pub first_block_index: i32,
    pub verdicts: Vec<JsVerdict>,
}

#[napi(object)]
pub struct JsEgressVerdict {
    pub kind: String,
    pub is_pass: bool,
    /// Populated for EgressBlock verdicts. Empty string on Pass.
    pub egress_reason: String,
    pub input_hash: String,
    pub sequence: u32,
}

#[napi]
pub async fn firewall_evaluate_messages(
    messages: Vec<JsChatMessage>,
    base_sequence: u32,
) -> Result<JsConversationVerdict> {
    // OC-01 guard — same as firewall_evaluate.
    let init_ok: &std::result::Result<(), String> = INIT_RESULT.get_or_init(|| {
        init().map_err(|e: firewall_core::FirewallInitError| e.to_string())
    });
    if let Err(e) = init_ok {
        return Err(napi::Error::from_reason(format!(
            "firewall not initialised (OC-01): {}. Call firewall_init() at startup.",
            e
        )));
    }

    let core_messages: Vec<ChatMessage> = messages
        .into_iter()
        .map(|m| ChatMessage { role: m.role, content: m.content })
        .collect();

    let cv = evaluate_messages(&core_messages, base_sequence as u64);

    let js_verdicts: Vec<JsVerdict> = cv.verdicts.iter().map(|v| {
        let block_reason = v.audit.block_reason
            .as_ref()
            .map(stable_block_reason)
            .unwrap_or_default();
        JsVerdict {
            kind: stable_verdict_kind(&v.kind),
            is_pass: v.is_pass(),
            channel_a_decision: stable_channel_decision(&v.channel_a.decision),
            channel_b_decision: stable_channel_decision(&v.channel_b.decision),
            elapsed_us: v.audit.total_elapsed_us.min(u32::MAX as u64) as u32,
            input_hash: v.audit.input_hash.clone(),
            sequence: v.audit.sequence.min(u32::MAX as u64) as u32,
            block_reason,
        }
    }).collect();

    Ok(JsConversationVerdict {
        is_pass: cv.is_pass,
        first_block_index: cv.first_block_index.map(|i| i as i32).unwrap_or(-1),
        verdicts: js_verdicts,
    })
}

#[napi]
pub async fn firewall_evaluate_output(
    prompt: String,
    response: String,
    sequence: u32,
) -> Result<JsEgressVerdict> {
    let init_ok: &std::result::Result<(), String> = INIT_RESULT.get_or_init(|| {
        init().map_err(|e: firewall_core::FirewallInitError| e.to_string())
    });
    if let Err(e) = init_ok {
        return Err(napi::Error::from_reason(format!(
            "firewall not initialised (OC-01): {}. Call firewall_init() at startup.",
            e
        )));
    }

    let prompt = PromptInput::new(prompt)
        .map_err(|e| napi::Error::from_reason(format!("invalid prompt for egress evaluation: {}", stable_block_reason(&e))))?;
    let ev = evaluate_output(&prompt, &response, sequence as u64)
        .map_err(napi::Error::from_reason)?;

    let (input_hash, seq) = match &ev.audit {
        Some(audit) => (
            audit.input_hash.clone(),
            audit.sequence.min(u32::MAX as u64) as u32,
        ),
        None => (String::new(), sequence),
    };

    Ok(JsEgressVerdict {
        kind: stable_verdict_kind(&ev.kind),
        is_pass: ev.is_pass(),
        egress_reason: ev
            .egress_reason
            .as_ref()
            .map(stable_egress_reason)
            .unwrap_or_default(),
        input_hash,
        sequence: seq,
    })
}

fn stable_egress_reason(r: &firewall_core::EgressBlockReason) -> String {
    use firewall_core::EgressBlockReason::*;
    match r {
        SystemPromptLeakage { detail } => format!("SystemPromptLeakage:{}", detail),
        PiiDetected { pii_type } => format!("PiiDetected:{}", pii_type),
        HarmfulContent { category } => format!("HarmfulContent:{}", category),
        Other { detail } => format!("Other:{}", detail),
    }
}
