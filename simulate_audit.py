import json
import time
import os

AUDIT_FILE = "simulated_audit.ndjson"

def append_record(verdict):
    record = {
        "schema_version": 1,
        "sequence": int(time.time() * 1000),
        "verdict_kind": verdict,
        "input_hash": "test",
        "total_elapsed_us": 100,
        "decided_at_ns": int(time.time() * 1_000_000_000)
    }
    with open(AUDIT_FILE, "a") as f:
        f.write(json.dumps(record) + "\n")

if os.path.exists(AUDIT_FILE):
    os.remove(AUDIT_FILE)

print(f"Simulating audit trail in {AUDIT_FILE}...")

# 1. Add 10 Pass records
for _ in range(10):
    append_record("Pass")
    time.sleep(0.1)

# 2. Add 10 DiagnosticAgreement records (should trigger >5% alert)
for _ in range(10):
    append_record("DiagnosticAgreement")
    time.sleep(0.1)

# 3. Add a DiagnosticDisagreement
append_record("DiagnosticDisagreement")

print("Simulation finished.")
