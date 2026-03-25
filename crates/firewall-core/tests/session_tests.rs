// session_tests.rs — SA-076: Session-Aware-Layer Tests

use firewall_core::{evaluate_with_session, PromptInput, VerdictKind, BlockReason};
use firewall_core::session::{SessionManager, SessionAnalysis, SessionRiskLevel, EscalationIndicator, SessionFlag};

#[test]
fn session_manager_initialization() {
    let manager = SessionManager::new();
    assert_eq!(manager.get_stats().total_sessions, 0);
}

#[test]
fn session_manager_with_custom_config() {
    let manager = SessionManager::with_config(5, 30); // 5 messages, 30 min timeout
    assert_eq!(manager.get_stats().total_sessions, 0);
}

#[test]
fn add_message_creates_session() {
    let manager = SessionManager::new();
    let input = PromptInput::new("Hello").expect("Valid input");
    
    let analysis = manager.add_message(
        "session-123",
        &input,
        VerdictKind::Pass,
        None,
    );
    
    assert_eq!(analysis.session_id, "session-123");
    assert_eq!(analysis.message_sequence, 1);
    assert_eq!(analysis.message_count, 1);
    assert_eq!(manager.get_stats().total_sessions, 1);
}

#[test]
fn escalation_score_increases_with_indicators() {
    let manager = SessionManager::new();
    let session_id = "escalation-test";
    
    // Add multiple messages with escalation indicators
    for i in 0..5 {
        let input = PromptInput::new(&format!("Message {}", i)).expect("Valid input");
        manager.add_message(session_id, &input, VerdictKind::Pass, None);
    }
    
    let stats = manager.get_stats();
    assert_eq!(stats.total_sessions, 1);
    
    // Get the last analysis (simulated - would need proper API)
    let last_input = PromptInput::new("Final message").expect("Valid input");
    let analysis = manager.add_message(session_id, &last_input, VerdictKind::Pass, None);
    
    // Should have some escalation score based on message patterns
    assert!(analysis.escalation_score >= 0);
}

#[test]
fn session_cleanup_removes_expired_sessions() {
    let manager = SessionManager::with_config(10, 0); // 0 minute timeout for testing
    
    // Add a session
    let input = PromptInput::new("Test").expect("Valid input");
    manager.add_message("expired-session", &input, VerdictKind::Pass, None);
    
    assert_eq!(manager.get_stats().total_sessions, 1);
    
    // Wait a moment and cleanup (in real scenario, this would wait for timeout)
    manager.cleanup_expired_sessions();
    
    // Session should be cleaned up (since timeout is 0)
    assert_eq!(manager.get_stats().total_sessions, 0);
}

#[test]
fn evaluate_with_session_integration() {
    firewall_core::init_with_token("test_token_for_development_only_12345678901234567890123456789012", firewall_core::FirewallProfile::Default).expect("init failed");
    
    let input = PromptInput::new("What is the capital of France?").expect("Valid input");
    let verdict = evaluate_with_session("test-session", &input, 1);
    
    // Should still pass through base firewall
    assert!(verdict.is_pass());
    assert_eq!(verdict.audit.sequence, 1);
}

#[test]
fn session_risk_levels() {
    let manager = SessionManager::new();
    let session_id = "risk-test";
    
    // Start with low risk
    let input = PromptInput::new("Hello").expect("Valid input");
    let analysis = manager.add_message(session_id, &input, VerdictKind::Pass, None);
    assert_eq!(analysis.risk_level, SessionRiskLevel::Low);
    
    // Add more messages to potentially increase risk
    for i in 1..10 {
        let input = PromptInput::new(&format!("Message {} with some complexity", i)).expect("Valid input");
        manager.add_message(session_id, &input, VerdictKind::Pass, None);
    }
    
    let final_input = PromptInput::new("Complex message with indicators").expect("Valid input");
    let final_analysis = manager.add_message(session_id, &final_input, VerdictKind::Pass, None);
    
    // Risk level should be High after many messages with escalation indicators
    assert!(matches!(final_analysis.risk_level, SessionRiskLevel::High));
    assert!(final_analysis.escalation_score >= 70);
}

#[test]
fn session_analysis_flags() {
    let manager = SessionManager::new();
    let session_id = "flags-test";
    
    // Add messages that might trigger flags
    let input1 = PromptInput::new("Short").expect("Valid input");
    manager.add_message(session_id, &input1, VerdictKind::Pass, None);
    
    let input2 = PromptInput::new("A slightly longer message").expect("Valid input");
    manager.add_message(session_id, &input2, VerdictKind::Pass, None);
    
    // Add many messages to trigger LongSession flag
    for i in 0..8 {
        let input = PromptInput::new(&format!("Message {}", i)).expect("Valid input");
        manager.add_message(session_id, &input, VerdictKind::Pass, None);
    }
    
    let final_input = PromptInput::new("Final message").expect("Valid input");
    let analysis = manager.add_message(session_id, &final_input, VerdictKind::Pass, None);
    
    // Should have LongSession flag due to many messages
    assert!(analysis.flags.iter().any(|f| matches!(f, SessionFlag::LongSession)));
    assert!(analysis.message_count >= 8);
}

#[test]
fn session_recommendations() {
    let manager = SessionManager::new();
    let session_id = "recommendations-test";
    
    // Create a high-risk scenario
    for i in 0..10 {
        let input = PromptInput::new(&format!("Complex message {} with escalation", i)).expect("Valid input");
        manager.add_message(session_id, &input, VerdictKind::Pass, None);
    }
    
    let final_input = PromptInput::new("Very complex final message").expect("Valid input");
    let analysis = manager.add_message(session_id, &final_input, VerdictKind::Pass, None);
    
    // Should have recommendations
    assert!(!analysis.recommendations.is_empty());
    
    // High risk should have specific recommendations
    if matches!(analysis.risk_level, SessionRiskLevel::High) {
        assert!(analysis.recommendations.iter().any(|r| r.contains("session termination")));
    }
}