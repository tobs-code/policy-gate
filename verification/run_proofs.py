#!/usr/bin/env python3
"""
run_proofs.py — Execute all Z3 proof obligations and report results.

Usage:
    python verification/run_proofs.py

Uses z3.Z3_eval_smtlib2_string to evaluate each SMT2 file in full,
then matches the output lines against the expected annotations.
"""

import re
import sys
import z3

# ─── Runner ───────────────────────────────────────────────────────────────────

EXPECTED_RE = re.compile(r'\(check-sat\)\s*;[^\n]*expected:\s*(\w+)')
ECHO_RE      = re.compile(r'\(echo\s+"([^"]+)"\)')

def run_file(path: str) -> tuple[int, int]:
    with open(path) as f:
        content = f.read()

    echo_match = ECHO_RE.search(content)
    label = echo_match.group(1) if echo_match else path

    print(f"\n{'─' * 60}")
    print(f"  {label}")
    print(f"  File: {path}")
    print(f"{'─' * 60}")

    # Evaluate the whole file — Z3_eval_smtlib2_string returns one line per
    # (check-sat) / (echo) call, space-separated.
    # Each file gets a fresh context to avoid set-logic/set-option conflicts.
    ctx = z3.Context()
    raw = z3.Z3_eval_smtlib2_string(ctx.ref(), content)
    # Output is newline-separated tokens
    output_tokens = [t.strip() for t in raw.strip().splitlines() if t.strip()]

    expected_list = [m.group(1) for m in EXPECTED_RE.finditer(content)]

    # Build PO labels from comments just before each check-sat
    po_labels = []
    for m in EXPECTED_RE.finditer(content):
        # Look backwards in content for the nearest ─── PO- comment
        snippet = content[:m.start()]
        po_match = re.findall(r';\s*─+\s*(PO-\S+[^\n]*)', snippet)
        po_labels.append(po_match[-1].strip() if po_match else f"check {len(po_labels)+1}")

    # Filter output to only sat/unsat/unknown lines (skip echo lines)
    result_tokens = [t for t in output_tokens if t in ('sat', 'unsat', 'unknown')]

    passed = failed = 0
    for i, (exp, po) in enumerate(zip(expected_list, po_labels)):
        act = result_tokens[i] if i < len(result_tokens) else "missing"
        ok  = act == exp
        sym = "✓" if ok else "✗ FAIL"
        print(f"  [{sym}] {po}  (expected={exp}, got={act})")
        if ok: passed += 1
        else:  failed += 1

    return passed, failed


# ─── Main ─────────────────────────────────────────────────────────────────────

FILES = [
    "verification/channel_a.smt2",
    "verification/voter.smt2",
    "verification/rule_engine.smt2",
]

total_passed = total_failed = 0
for f in FILES:
    try:
        p, fail = run_file(f)
    except FileNotFoundError:
        print(f"\n  ✗ MISSING: {f} — file not found, skipping")
        total_failed += 1
        continue
    except Exception as e:
        print(f"\n  ✗ ERROR in {f}: {e}")
        total_failed += 1
        continue
    total_passed += p
    total_failed += fail

print(f"\n{'═' * 60}")
print(f"  TOTAL: {total_passed} passed, {total_failed} failed")
print(f"{'═' * 60}\n")
sys.exit(0 if total_failed == 0 else 1)
