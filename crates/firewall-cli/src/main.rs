// firewall-cli — stdin-line evaluator for benchmark scripts.
//
// Usage: echo "some prompt" | firewall-cli
//        firewall-cli < prompts.txt
//
// Output per line: "PASS\t<prompt>" or "BLOCK\t<prompt>"
// Exit code: 0 always (errors are reported as BLOCK lines).

use firewall_core::{evaluate_raw, init};
use std::io::{self, BufRead};

fn main() {
    init().expect("firewall init failed");
    let stdin = io::stdin();
    for (i, line) in stdin.lock().lines().enumerate() {
        let prompt = match line {
            Ok(l) => l,
            Err(e) => { eprintln!("read error: {}", e); continue; }
        };
        if prompt.trim().is_empty() { continue; }
        let verdict = evaluate_raw(prompt.clone(), i.min(u64::MAX as usize) as u64);
        let label = if verdict.is_pass() { "PASS" } else { "BLOCK" };
        println!("{}\t{:?}\t{}", label, verdict.kind, prompt);
    }
}
