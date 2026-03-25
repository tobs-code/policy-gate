#!/usr/bin/env python3
"""
check_pattern_hash.py — Detect intent pattern changes that require Z3 re-proof.

Computes a SHA-256 over the safety-critical source files that define the
allowlist and forbidden-pattern tables. If the hash differs from the stored
baseline in .pattern_hash, warns that Z3 models may need updating.

Files tracked:
  - crates/firewall-core/src/fsm/intent_patterns.rs  (Channel A allowlist)
  - crates/firewall-core/src/rule_engine/rules.rs     (Channel B rules)
  - crates/firewall-core/src/fsm/mod.rs               (FSM + forbidden patterns)
  - verification/channel_a.smt2
  - verification/voter.smt2
  - verification/rule_engine.smt2

Usage:
    python verification/check_pattern_hash.py           # check only (exit 1 on mismatch)
    python verification/check_pattern_hash.py --update  # update stored hash

In CI, run WITHOUT --update. Mismatch = PR author must re-run Z3 proofs and
update the hash manually (python verification/check_pattern_hash.py --update).
"""

import argparse
import hashlib
import sys
from pathlib import Path

TRACKED_FILES = [
    "crates/firewall-core/src/fsm/intent_patterns.rs",
    "crates/firewall-core/src/rule_engine/rules.rs",
    "crates/firewall-core/src/fsm/mod.rs",
    "verification/channel_a.smt2",
    "verification/voter.smt2",
    "verification/rule_engine.smt2",
]

HASH_FILE = Path("verification/.pattern_hash")


def compute_hash() -> str:
    h = hashlib.sha256()
    for rel in sorted(TRACKED_FILES):
        p = Path(rel)
        if not p.exists():
            print(f"  [WARN] Tracked file missing: {rel}", file=sys.stderr)
            continue
        h.update(rel.encode())
        h.update(p.read_bytes())
    return h.hexdigest()


def main():
    parser = argparse.ArgumentParser(description="Detect safety-critical pattern changes.")
    parser.add_argument("--update", action="store_true",
                        help="Update stored hash to current state (run after Z3 re-proof)")
    args = parser.parse_args()

    current = compute_hash()

    if args.update:
        HASH_FILE.write_text(current + "\n", encoding="utf-8")
        print(f"  [OK] Pattern hash updated: {current[:16]}…")
        sys.exit(0)

    if not HASH_FILE.exists():
        print("  [INFO] No .pattern_hash baseline found — creating it now.")
        HASH_FILE.write_text(current + "\n", encoding="utf-8")
        print(f"  [OK] Baseline created: {current[:16]}…")
        sys.exit(0)

    stored = HASH_FILE.read_text(encoding="utf-8").strip()

    if current == stored:
        print(f"  [OK] Pattern hash matches baseline ({current[:16]}…) — Z3 models up to date.")
        sys.exit(0)
    else:
        print("  [WARN] Pattern hash mismatch — safety-critical sources have changed.")
        print(f"  Stored:  {stored[:16]}…")
        print(f"  Current: {current[:16]}…")
        print()
        print("  Changed files may affect Z3 proof obligations. Steps required:")
        print("    1. Review the changes in the tracked files above.")
        print("    2. Update the Z3 SMT2 models if patterns changed.")
        print("    3. Run: python verification/run_proofs.py")
        print("    4. If all POs pass: python verification/check_pattern_hash.py --update")
        print("    5. Commit the updated .pattern_hash alongside your changes.")
        sys.exit(1)


if __name__ == "__main__":
    main()
