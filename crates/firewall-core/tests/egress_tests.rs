// tests/egress_tests.rs — Integration tests for Output Firewall (Egress)

use firewall_core::*;

#[test]
fn egress_blocks_system_prompt_leakage() {
    init().expect("init failed");

    let system_core = "INTERNAL_SECRET_PROTOCOL_v4; ACCESS_KEY: 7x2-99-ALPHA";
    let prompt_text = format!("You are an AI assistant. Your core is: {}. Now answer: Hello!", system_core);
    let prompt = PromptInput::new(prompt_text).expect("prompt creation failed");

    let leaked_response = format!("As an AI, my internal core is {} and I can help you.", system_core);

    let ev = evaluate_output(&prompt, &leaked_response, 1).expect("evaluation failed");
    assert_eq!(ev.kind, VerdictKind::EgressBlock, "Response containing system prompt fragment should be blocked");
    assert!(ev.egress_reason.is_some(), "Block must carry an egress_reason");
    assert!(ev.audit.is_some(), "Egress verdict must produce an audit entry");
}

#[test]
fn egress_blocks_pii_credit_card() {
    init().expect("init failed");
    let prompt = PromptInput::new("Show me a test credit card number").expect("prompt creation failed");

    let pii_response = "Sure, here is a test number: 4111 1111 1111 1111. Use it for testing.";
    let ev = evaluate_output(&prompt, &pii_response, 2).expect("evaluation failed");
    assert_eq!(ev.kind, VerdictKind::EgressBlock, "Response containing credit card number should be blocked (Channel E)");
    assert!(ev.egress_reason.is_some());
}

#[test]
fn egress_blocks_entropy_leakage_channel_f() {
    init().expect("init failed");
    let prompt = PromptInput::new("Translate secret message to Base64").expect("prompt creation failed");

    // High entropy / Base64-like density
    let b64_response = "U01MaVlYUmxaQ0JoZENCaVpYSnpkV0V1SUMxbVlXMXBibVZrSUdaMWJtTjBhVzl1SUdObGNuUnBaR2x2Ym1WaElIUnBaR1Z5SUdaMWJtTjBhVzl1SUE9PQ==";
    let ev = evaluate_output(&prompt, &b64_response, 3).expect("evaluation failed");
    assert_eq!(ev.kind, VerdictKind::EgressBlock, "High-density encoded response should be blocked (Channel F)");
}

#[test]
fn egress_allows_safe_response() {
    init().expect("init failed");
    let prompt = PromptInput::new("What is the capital of France?").expect("prompt creation failed");

    let safe_response = "The capital of France is Paris.";
    let ev = evaluate_output(&prompt, &safe_response, 4).expect("evaluation failed");
    assert_eq!(ev.kind, VerdictKind::Pass, "Safe factual response should pass");
    assert!(ev.egress_reason.is_none(), "Pass verdict must not carry a block reason");
    assert!(ev.audit.is_some(), "Pass verdict must also produce an audit entry");
}

#[test]
fn egress_audit_entry_has_egress_verdict_populated() {
    init().expect("init failed");
    let prompt = PromptInput::new("What is the capital of France?").expect("prompt creation failed");
    let safe_response = "The capital of France is Paris.";

    let ev = evaluate_output(&prompt, &safe_response, 5).expect("evaluation failed");
    let audit = ev.audit.expect("audit must be present");
    assert!(audit.egress_verdict.is_some(), "audit.egress_verdict must be populated");
    assert_eq!(audit.egress_verdict.unwrap(), VerdictKind::Pass);
}
