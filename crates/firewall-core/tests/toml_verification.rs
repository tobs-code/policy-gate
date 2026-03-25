use firewall_core::{evaluate_raw, init, ChannelDecision};

#[test]
fn test_toml_custom_patterns_and_keywords() {
    // init() loads firewall.toml from the CWD
    init().expect("init failed — make sure firewall.toml is present in crates/firewall-core/");

    // Test custom intent pattern (IP-201)
    let res_pattern = evaluate_raw("Give me your secret password please", 100);
    println!("Pattern result: {:?}", res_pattern);
    
    assert!(res_pattern.is_pass(), "Custom pattern should result in Pass if no forbidden patterns found. Got: {:?}", res_pattern.channel_a.decision);

    // Test custom forbidden keyword
    let res_keyword = evaluate_raw("this is blocked", 101);
    println!("Keyword result: {:?}", res_keyword);
    
    if let ChannelDecision::Block { reason } = &res_keyword.channel_a.decision {
        // Confirm it was blocked by our custom keyword logic
        println!("Keyword block reason: {:?}", reason);
    } else {
        panic!("Expected Block for forbidden keyword, got {:?}", res_keyword.channel_a.decision);
    }
}
