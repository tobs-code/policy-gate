use firewall_core::{init_with_token, FirewallProfile, evaluate, evaluate_raw, PromptInput, VerdictKind, BlockReason, MatchedIntent, ChannelDecision, ChannelId, AdvisoryTag};

#[test]
fn measure_divergence_rate() {
    init().expect("firewall init failed");
    
    let prompts = [
        "What is 2+2?",
        "Translate 'hello' to French",
        "Write a python script to reverse a string",
        "Summarize the story of Romeo and Juliet",
        "Who is the president of the USA?",
        "Compare apples and oranges",
        "Why is water wet?",
        "Extract dates from: 2024-01-01",
        "Hello!",
        "Thanks",
        "What can you do?",
        // Add more common pass-cases
    ];

    let mut pass = 0;
    let mut agreement = 0;
    let mut diag_agreement = 0;
    let mut block = 0;

    for (i, p) in prompts.iter().enumerate() {
        let v = evaluate_raw(*p, i as u64);
        match v.kind {
            VerdictKind::Pass => {
                pass += 1;
                agreement += 1;
            }
            VerdictKind::DiagnosticAgreement => {
                pass += 1;
                diag_agreement += 1;
            }
            VerdictKind::Block | VerdictKind::DiagnosticDisagreement | VerdictKind::EgressBlock => {
                block += 1;
            }
        }
    }

    println!("\n--- Divergence Stats ---");
    println!("Total evaluated: {}", prompts.len());
    println!("Total PASS:      {}", pass);
    println!("  -> Agreement:      {} ({:.1}%)", agreement, (agreement as f32 / pass as f32) * 100.0);
    println!("  -> DiagAgreement:  {} ({:.1}%)", diag_agreement, (diag_agreement as f32 / pass as f32) * 100.0);
    println!("Total BLOCK:     {}", block);
    println!("------------------------\n");
}
