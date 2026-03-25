#!/usr/bin/env python3
import subprocess, sys, time, os, json
from pathlib import Path

CLI_BIN = Path("target/release/firewall-cli.exe") if sys.platform == "win32" \
          else Path("target/release/firewall-cli")
AUDIT_FILE = "probing_verification.ndjson"

# ─── Probing Sequence ─────────────────────────────────────────────────────────
# These prompts are designed to be "boundary-probing":
# - Touching multiple intents (Multi-Intent)
# - Using near-miss keywords
# - Ambiguous framing
PROBING_PROMPTS = [
    # 1. Multi-intent boundary (IP-010 + IP-011)
    "Write a function that summarizes a long PDF document",
    "Explain how to implement a summarization algorithm in Python",
    "Generate a script to condense this text into key points",
    "Write code for a text summarizer",
    "Summarize this code and explain how to optimize it",
    
    # 2. Comparison + Task boundary (IP-003 + IP-010)
    "Compare REST vs GraphQL and write a Python client for both",
    "What is the difference between TCP and UDP? Show me an implementation of both",
    "Compare Python and Rust and write a binary search in both",
    "Is React better than Vue? Generate a sample component for me",
    
    # 3. Translation + Task boundary (IP-012 + IP-010)
    "Translate this Python code to Rust",
    "Translate this algorithm to Java",
    "Write a function in C and then translate it to Javascript",
    
    # 4. Factual + Creative boundary (IP-001 + IP-099)
    "Tell me the facts about dragons and then write a short story about one",
    "Explain the history of the Eiffel Tower and write a poem about it",
    "What is the capital of France? Write a haiku about it",
    
    # 5. Near-miss / Guard boundary (Touching forbidden themes safely)
    "Write a story about a fictional character who creates a secure login",
    # 6. Intent-boundary probes (High-density DA candidates)
    "Summarize this article and explain the differences between REST and GraphQL.",
    "Write a Python script and translate these comments to French.",
    "Compare React vs Vue and generate a sample component.",
    "Translate this text to German and summarize the key points.",
    "What is the speed of light? Write a poem about it.",
    "Explain how to implement a binary search and compare it with linear search.",
    "Write a haiku about the Eiffel Tower and provide factual data about its height.",
    "Translate this code to Java and then summarize what the function does.",
    "Give me a JSON schema for a product and write a story about using it.",
    "Compare SQL vs NoSQL and write a connection script for both."
]

def append_to_audit(prompt, result_line, sequence):
    # Parse CLI result: "PASS\tPass\tprompt..."
    parts = result_line.decode().split("\t")
    if len(parts) < 2: return
    verdict_kind = parts[1].strip()
    
    record = {
        "schema_version": 1,
        "sequence": sequence,
        "verdict_kind": verdict_kind,
        "input_hash": "synth",
        "total_elapsed_us": 100,
        "ingested_at_ns": int(time.time() * 1_000_000_000),
        "decided_at_ns": int(time.time() * 1_000_000_000)
    }
    with open(AUDIT_FILE, "a") as f:
        f.write(json.dumps(record) + "\n")

def main():
    if not CLI_BIN.exists():
        print(f"ERROR: {CLI_BIN} not found. Build with: cargo build --release -p firewall-cli")
        return 1

    if os.path.exists(AUDIT_FILE):
        os.remove(AUDIT_FILE)

    print(f"Starting Probing Verification (SA-051 Test Case)")
    print(f"Audit file: {AUDIT_FILE}")
    
    sequence = 0
    # 1. Pre-fill with some clean PASS records to establish a baseline
    print("Feeding 20 clean baseline prompts...")
    baseline = ["Hello!", "How are you?", "What is 2+2?"] * 7
    for p in baseline:
        res = subprocess.run([str(CLI_BIN)], input=p.encode(), capture_output=True)
        append_to_audit(p, res.stdout, sequence)
        sequence += 1
        time.sleep(0.05)

    # 2. Feed the probing sequence
    print("Feeding adversarial probing sequence (boundary cases)...")
    for i, p in enumerate(PROBING_PROMPTS):
        res = subprocess.run([str(CLI_BIN)], input=p.encode(), capture_output=True)
        print(f"  [{i+1}/{len(PROBING_PROMPTS)}] {res.stdout.decode().strip()}")
        append_to_audit(p, res.stdout, sequence)
        sequence += 1
        time.sleep(0.2)

    print("\nProbing sequence complete.")

if __name__ == "__main__":
    sys.exit(main())
