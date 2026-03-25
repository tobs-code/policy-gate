use firewall_core::*;

#[test]
fn test_code_assistant_profile_filtering() {
    // Initialize with CodeAssistant profile
    // Factual (IP-001) should pass
    // Translation (IP-012) should be blocked (downgraded)
    #[allow(deprecated)]
    let _ = init_with_profile(FirewallProfile::CodeAssistant);

    let res_factual = evaluate_raw("What is a linked list?", 1);
    assert!(res_factual.is_pass(), "Factual should pass in CodeAssistant profile");
    
    if let ChannelDecision::Pass { intent } = &res_factual.channel_a.decision {
        assert_eq!(intent, &MatchedIntent::QuestionFactual);
    } else {
        panic!("Expected Pass decision for factual query, got {:?}", res_factual.channel_a.decision);
    }

    let res_translate = evaluate_raw("Translate 'hello' to German", 2);
    assert!(!res_translate.is_pass(), "Translation should be blocked in CodeAssistant profile");
    
    // Check that it was blocked appropriately
    assert!(matches!(res_translate.channel_a.decision, ChannelDecision::Block { .. }));
}
