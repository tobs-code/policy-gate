#!/usr/bin/env python3
"""
operator_review.py — Side-by-Side Operator Review Tool for DiagnosticDisagreement Events.

PURPOSE:
    Provides operators with a detailed side-by-side comparison of Channel A (FSM)
    vs Channel B (Rule Engine) decisions when they disagree. Enables informed
    decisions about rule engine tuning and pattern adjustments.

ARCHITECTURE:
    ┌─────────────────────────────────────────────────────────────────────────┐
    │                        operator_review.py                               │
    ├─────────────────────────────────────────────────────────────────────────┤
    │                                                                         │
    │  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────────────┐  │
    │  │ NDJSON      │    │ Input       │    │ Decision                    │  │
    │  │ Audit Log   │───▶│ Reconciler  │───▶│ Analyzer                    │  │
    │  │ Parser      │    │             │    │                             │  │
    │  └─────────────┘    └─────────────┘    └─────────────────────────────┘  │
    │         │                  │                       │                    │
    │         ▼                  ▼                       ▼                    │
    │  ┌─────────────────────────────────────────────────────────────────┐   │
    │  │                    Side-by-Side Renderer                        │   │
    │  │  ┌─────────────────────┐    ┌─────────────────────┐            │   │
    │  │  │ Channel A (FSM)     │    │ Channel B (Rules)   │            │   │
    │  │  │ - Decision          │    │ - Decision          │            │   │
    │  │  │ - Intent/Pattern    │    │ - Rule ID           │            │   │
    │  │  │ - Matched Fragment │    │ - Block Reason      │            │   │
    │  │  │ - Normalised Input │    │ - Trigger Keywords  │            │   │
    │  │  └─────────────────────┘    └─────────────────────┘            │   │
    │  └─────────────────────────────────────────────────────────────────┘   │
    │         │                                                              │
    │         ▼                                                              │
    │  ┌─────────────────────────────────────────────────────────────────┐   │
    │  │                    Operator Action Recorder                     │   │
    │  │  - Acknowledge (true positive)                                  │   │
    │  │  - Add Pattern (FP in Channel A)                                │   │
    │  │  - Adjust Rule (FP in Channel B)                                │   │
    │  │  - Export to CSV/JSON                                           │   │
    │  └─────────────────────────────────────────────────────────────────┘   │
    │                                                                         │
    └─────────────────────────────────────────────────────────────────────────┘

USAGE:
    # Review all DiagnosticDisagreement events
    python operator_review.py --input audit.ndjson

    # Review specific sequence
    python operator_review.py --input audit.ndjson --sequence 42

    # Interactive mode (walk through all DD events)
    python operator_review.py --input audit.ndjson --interactive

    # Export findings for rule tuning
    python operator_review.py --input audit.ndjson --export findings.json

    # With optional input text database
    python operator_review.py --input audit.ndjson --text-db inputs.db

EXIT CODES:
    0 - Success
    1 - Input error / file not found
    2 - No DiagnosticDisagreement events found
    3 - Operator action recorded (for CI/CD integration)

RELATED:
    - disagreement_analytics.py: Aggregate statistics
    - voter.rs: 1oo2D voter logic
    - types.rs: ChannelResult, BlockReason types
"""

import argparse
import json
import re
import sqlite3
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional

# Try to use tomllib (Python 3.11+), fallback to tomli
try:
    import tomllib
except ImportError:
    import tomli as tomllib


# ─── Data Types ───────────────────────────────────────────────────────────────


class OperatorAction(str, Enum):
    """Actions an operator can take on a DiagnosticDisagreement event."""

    ACKNOWLEDGE = "acknowledge"  # True positive — keep block
    ADD_PATTERN = "add_pattern"  # FP in Channel A — add allowlist pattern (manual)
    ADD_PATTERN_AUTO = "add_pattern_auto"  # FP in Channel A — auto-generate regex
    ADJUST_RULE = "adjust_rule"  # FP in Channel B — adjust rule
    FALSE_POSITIVE = "false_positive"  # Both channels wrong — both need tuning
    TRUE_POSITIVE = "true_positive"  # Correctly blocked — no action needed
    DEFER = "defer"  # Needs more investigation


# ─── Regex Generation ───────────────────────────────────────────────────────────


def generate_regex_from_text(input_text: str) -> str:
    """
    Generate a regex pattern from an input text fragment.
    
    This function analyzes the input text and creates an appropriate regex pattern
    that can be used in the firewall allowlist. It handles:
    - Special regex characters (escaping)
    - Leetspeak patterns (0->o, 1->l, 3->e, etc.)
    - Common obfuscation techniques
    - Word boundaries for exact matching
    
    Args:
        input_text: The text fragment to generate a regex for
        
    Returns:
        A regex pattern string suitable for firewall.toml
    """
    if not input_text:
        return ""
    
    # Step 1: Basic escaping of special regex characters using re.escape()
    escaped = re.escape(input_text)
    
    # Step 2: Detect and handle leetspeak patterns
    leet_map = {
        "0": "[0o]", "1": "[1li]", "2": "[2z]", "3": "[3e]", "4": "[4a]",
        "5": "[5s]", "6": "[6g]", "7": "[7t]", "8": "[8b]", "9": "[9g]",
        "@": "[@a]", "$": "[$s]", "|": "[|Il]"
    }
    
    has_leetspeak = any(c in leet_map for c in input_text.lower())
    
    # Step 3: Check for mixed case (case-insensitive matching)
    has_mixed_case = input_text.lower() != input_text and input_text.upper() != input_text
    
    # Step 4: Build the final pattern
    if has_leetspeak:
        # Create pattern with leetspeak alternatives
        # Start with escaped version, then substitute leet chars
        pattern = escaped  # Use already escaped string as base
        for leet_char, replacement in leet_map.items():
            # Replace the escaped version of the leet char
            escaped_leet = re.escape(leet_char)
            pattern = pattern.replace(escaped_leet, replacement)
        # Add case-insensitive flag note
        result = f"(?i){pattern}"
    elif has_mixed_case:
        # Case-insensitive match for mixed case
        result = f"(?i){escaped}"
    else:
        # Exact match (case-sensitive)
        result = escaped
    
    return result


def generate_toml_patch(pattern: str, reason: str, sequence_id: int = 0) -> str:
    """
    Generate a TOML patch snippet for the firewall configuration.
    
    Args:
        pattern: The regex pattern to add to the allowlist
        reason: Reason for adding this pattern (e.g., "Operator-Review: FP #<id>")
        sequence_id: Optional sequence ID for reference
        
    Returns:
        A TOML snippet ready to be added to firewall.toml
    """
    if not pattern:
        return "# No pattern provided"
    
    # Build the TOML snippet
    reason_text = reason if reason else f"Operator-Review: FP #{sequence_id}"
    
    toml_snippet = f'''[[intent_patterns.allowlist]]
pattern = "{pattern}"
reason = "{reason_text}"'''
    
    return toml_snippet


def write_toml_patch(pattern: str, reason: str, sequence_id: int = 0, toml_path: str = "firewall.toml") -> bool:
    """
    Write a TOML patch directly to the firewall.toml file.
    
    Args:
        pattern: The regex pattern to add to the allowlist
        reason: Reason for adding this pattern (e.g., "Operator-Review: FP #<id>")
        sequence_id: Optional sequence ID for reference
        toml_path: Path to the TOML config file (default: firewall.toml)
        
    Returns:
        True if successful, False if failed
    """
    if not pattern:
        print("  [ERROR] No pattern provided", file=sys.stderr)
        return False
    
    toml_file = Path(toml_path)
    
    # Check if firewall.toml exists, otherwise try firewall.example.toml
    if not toml_file.exists():
        example_path = Path("firewall.example.toml")
        if example_path.exists():
            print(f"  [INFO] {toml_path} not found, copying from firewall.example.toml")
            # Copy example to firewall.toml
            import shutil
            shutil.copy(example_path, toml_file)
        else:
            print(f"  [ERROR] No TOML config file found: {toml_path} or firewall.example.toml", file=sys.stderr)
            return False
    
    # Read existing TOML
    try:
        with open(toml_file, "rb") as f:
            config = tomllib.load(f)
    except Exception as e:
        print(f"  [ERROR] Failed to parse TOML: {e}", file=sys.stderr)
        return False
    
    # Ensure intent_patterns section exists
    if "intent_patterns" not in config:
        config["intent_patterns"] = {}
    if "allowlist" not in config["intent_patterns"]:
        config["intent_patterns"]["allowlist"] = []
    
    # Add new pattern entry
    reason_text = reason if reason else f"Operator-Review: FP #{sequence_id}"
    new_entry = {
        "pattern": pattern,
        "reason": reason_text
    }
    config["intent_patterns"]["allowlist"].append(new_entry)
    
    # Write back to TOML file with proper formatting
    try:
        # First read existing content
        with open(toml_file, "r", encoding="utf-8") as f:
            content = f.read()
        
        # Now append the new entry
        with open(toml_file, "w", encoding="utf-8") as f:
            # Write header comment if not present
            if "intent_patterns.allowlist" not in content and "[[intent_patterns.allowlist]]" not in content:
                f.write("# Auto-generated allowlist patterns\n")
            
            # Append the new entry
            f.write(content)
            if not content.endswith('\n'):
                f.write('\n')
            f.write(f'\n[[intent_patterns.allowlist]]\n')
            f.write(f'pattern = "{pattern}"\n')
            f.write(f'reason = "{reason_text}"\n')
        
        print(f"  [OK] Pattern written to {toml_path}")
        return True
    except Exception as e:
        print(f"  [ERROR] Failed to write TOML: {e}", file=sys.stderr)
        return False


def extract_problematic_text(detail: "DisagreementDetail") -> Optional[str]:
    """
    Extract the problematic text from a DisagreementDetail for pattern generation.
    
    This function attempts to find the text that triggered the false positive
    by examining the available input text and channel analysis.
    
    Args:
        detail: The DisagreementDetail to extract text from
        
    Returns:
        The text fragment to create a pattern for, or None if not available
    """
    # Priority 1: Use original input text if available
    if detail.input_text:
        # If there's normalised text, the input was transformed
        if detail.normalised_text and detail.normalised_text != detail.input_text:
            # The original (non-normalised) input caused the FP
            return detail.input_text
        return detail.input_text
    
    # Priority 2: Try to get matched fragment from channel analysis
    if detail.channel_a.matched_fragment:
        return detail.channel_a.matched_fragment
    if detail.channel_b.matched_fragment:
        return detail.channel_b.matched_fragment
    
    # Priority 3: Use the matched pattern if available
    if detail.channel_a.matched_pattern:
        return detail.channel_a.matched_pattern
    if detail.channel_b.matched_pattern:
        return detail.channel_b.matched_pattern
    
    return None


@dataclass
class ChannelAnalysis:
    """Detailed analysis of a single channel's decision."""

    channel_id: str  # "A" or "B"
    decision_type: str  # "Pass" or "Block"
    decision_detail: str  # Intent (Pass) or BlockReason (Block)
    matched_pattern: Optional[str]  # Pattern ID or Rule ID
    matched_fragment: Optional[str]  # What triggered the match
    elapsed_us: int  # Evaluation time in microseconds

    def summary_line(self) -> str:
        """Single-line summary for compact display."""
        if self.decision_type == "Pass":
            return f"{self.channel_id}: PASS → {self.decision_detail}"
        else:
            return f"{self.channel_id}: BLOCK → {self.matched_pattern or self.decision_detail}"


@dataclass
class DisagreementDetail:
    """Complete analysis of a DiagnosticDisagreement event."""

    sequence: int
    timestamp: str
    input_hash: str
    input_text: Optional[str]  # From external source if available
    normalised_text: Optional[str]  # If input_text available
    channel_a: ChannelAnalysis
    channel_b: ChannelAnalysis
    advisory_score: Optional[int]  # Channel C score if present
    total_elapsed_us: int

    # Root cause analysis
    root_cause: str = ""
    recommendation: str = ""

    # Operator action (populated interactively)
    operator_action: Optional[OperatorAction] = None
    operator_notes: str = ""

    def get_root_cause(self) -> str:
        """Generate root cause analysis based on channel decisions."""
        if self.root_cause:
            return self.root_cause

        causes = []

        # Case 1: A passes, B blocks
        if (
            self.channel_a.decision_type == "Pass"
            and self.channel_b.decision_type == "Block"
        ):
            causes.append(
                "Channel A (FSM) matched an allowlist intent but Channel B (Rules) found a forbidden pattern."
            )

            # Check for confusable/obfuscation patterns
            if self.input_text and self.normalised_text:
                if self.input_text != self.normalised_text:
                    causes.append(
                        f"Input was normalised: '{self.input_text[:50]}...' → '{self.normalised_text[:50]}...'"
                    )

            # Check for leet-speak
            leet_chars = set("0123456789@$|")
            if self.input_text and any(c in leet_chars for c in self.input_text):
                causes.append(
                    "Leet-speak characters detected — may have bypassed FSM pattern matching."
                )

            self.root_cause = " ".join(causes)

        # Case 2: A blocks, B passes
        elif (
            self.channel_a.decision_type == "Block"
            and self.channel_b.decision_type == "Pass"
        ):
            causes.append(
                "Channel A (FSM) blocked via forbidden pattern but Channel B (Rules) found no violation."
            )
            causes.append(
                "Possible: Channel A has stricter payload keyword matching (FP-003/FP-004)."
            )
            self.root_cause = " ".join(causes)

        else:
            self.root_cause = (
                "Both channels agreed on different classifications — see details below."
            )

        return self.root_cause

    def get_recommendation(self) -> str:
        """Generate recommendation for operator action."""
        if self.recommendation:
            return self.recommendation

        if (
            self.channel_a.decision_type == "Pass"
            and self.channel_b.decision_type == "Block"
        ):
            # Channel B blocked, Channel A passed
            if (
                "leetspeak" in self.root_cause.lower()
                or "normalised" in self.root_cause.lower()
            ):
                self.recommendation = "Option 1: Keep block (likely true positive with obfuscation). Option 2: If legitimate, add intent pattern with stronger guard."
            else:
                self.recommendation = "Consider: (1) Adjust RE-004/RE-005 keywords if FP, (2) Add post-match guard to allowlist pattern if edge case."

        elif (
            self.channel_a.decision_type == "Block"
            and self.channel_b.decision_type == "Pass"
        ):
            self.recommendation = "Consider: (1) Loosen FP-003/FP-004 keyword list if false positive, (2) Add exception pattern for defensive/educational context."

        else:
            self.recommendation = "Review both channels for calibration."

        return self.recommendation


# ─── Data Loading ─────────────────────────────────────────────────────────────


def load_audit_log(path: str) -> list[dict]:
    """Load NDJSON audit log."""
    records = []
    errors = 0
    with open(path, encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as e:
                print(
                    f"  [WARN] Line {lineno}: JSON parse error — {e}", file=sys.stderr
                )
                errors += 1
    if errors:
        print(f"  [WARN] {errors} lines skipped due to parse errors.", file=sys.stderr)
    return records


def load_text_database(db_path: str) -> dict[str, tuple[str, str]]:
    """
    Load input text from SQLite database.

    Expected schema:
        CREATE TABLE inputs (
            hash TEXT PRIMARY KEY,
            input_text TEXT,
            normalised_text TEXT,
            created_at INTEGER
        );

    Returns: dict mapping hash -> (input_text, normalised_text)
    """
    if not Path(db_path).exists():
        print(f"  [WARN] Text database not found: {db_path}", file=sys.stderr)
        return {}

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    texts = {}
    try:
        cursor.execute("SELECT hash, input_text, normalised_text FROM inputs")
        for row in cursor:
            texts[row[0]] = (row[1], row[2])
    except sqlite3.OperationalError as e:
        print(f"  [WARN] Could not read text database: {e}", file=sys.stderr)
    finally:
        conn.close()

    return texts


# ─── Analysis ─────────────────────────────────────────────────────────────────


def parse_channel_result(result: dict, channel_letter: str) -> ChannelAnalysis:
    """Parse a ChannelResult dict into ChannelAnalysis."""
    decision = result.get("decision", {})
    decision_type = decision.get("type", "Unknown")

    if decision_type == "Pass":
        return ChannelAnalysis(
            channel_id=channel_letter,
            decision_type="Pass",
            decision_detail=decision.get("intent", "Unknown"),
            matched_pattern=decision.get("pattern_id"),
            matched_fragment=None,
            elapsed_us=result.get("elapsed_us", 0),
        )
    else:  # Block or Fault
        return ChannelAnalysis(
            channel_id=channel_letter,
            decision_type="Block",
            decision_detail=decision.get("reason", decision.get("detail", "Unknown")),
            matched_pattern=decision.get("pattern_id"),
            matched_fragment=None,
            elapsed_us=result.get("elapsed_us", 0),
        )


def parse_channel_result_from_record(
    result: Optional[dict], channel_letter: str
) -> Optional[ChannelAnalysis]:
    """Parse a ChannelResult dict from the audit record (v2 schema)."""
    if not result:
        return None

    decision = result.get("decision", {})
    decision_type = decision.get("type", "Unknown")

    if decision_type == "Pass":
        return ChannelAnalysis(
            channel_id=channel_letter,
            decision_type="Pass",
            decision_detail=decision.get("intent", "Unknown"),
            matched_pattern=decision.get("pattern_id"),
            matched_fragment=None,
            elapsed_us=result.get("elapsed_us", 0),
        )
    elif decision_type == "Block":
        return ChannelAnalysis(
            channel_id=channel_letter,
            decision_type="Block",
            decision_detail=decision.get("reason", "Unknown"),
            matched_pattern=decision.get("pattern_id"),
            matched_fragment=None,
            elapsed_us=result.get("elapsed_us", 0),
        )
    elif decision_type == "Fault":
        return ChannelAnalysis(
            channel_id=channel_letter,
            decision_type="Block",
            decision_detail=f"Fault: {decision.get('code', 'Unknown')}",
            matched_pattern=None,
            matched_fragment=None,
            elapsed_us=result.get("elapsed_us", 0),
        )
    return None


def analyze_disagreement(
    record: dict, text_db: dict[str, tuple[str, str]]
) -> Optional[DisagreementDetail]:
    """Analyze a single DiagnosticDisagreement audit record.

    Supports both v1 (basic) and v2 (detailed) audit schemas.
    v2 includes channel_a_result and channel_b_result for full side-by-side analysis.
    """
    if record.get("verdict_kind") != "DiagnosticDisagreement":
        return None

    # Extract basic info
    sequence = record.get("sequence", 0)
    timestamp_ns = record.get("decided_at_ns", 0)
    timestamp = (
        datetime.fromtimestamp(timestamp_ns / 1e9, tz=timezone.utc).isoformat()
        if timestamp_ns
        else "unknown"
    )
    input_hash = record.get("input_hash", "")
    schema_version = record.get("schema_version", 1)

    # Try to get input text from database
    input_text, normalised_text = text_db.get(input_hash, (None, None))

    # Parse block reason (v1 compatible)
    block_reason = record.get("block_reason", {})
    block_type = (
        block_reason.get("type", "Unknown")
        if isinstance(block_reason, dict)
        else str(block_reason)
    )
    block_pattern = (
        block_reason.get("pattern_id") if isinstance(block_reason, dict) else None
    )

    # Try to parse full ChannelResult from v2 schema
    channel_a_result = record.get("channel_a_result")
    channel_b_result = record.get("channel_b_result")

    channel_a = parse_channel_result_from_record(channel_a_result, "A")
    channel_b = parse_channel_result_from_record(channel_b_result, "B")

    # Fallback to v1 construction if v2 data not available
    if channel_a is None:
        channel_a = ChannelAnalysis(
            channel_id="A",
            decision_type="Block" if block_type else "Unknown",
            decision_detail=block_pattern or block_type,
            matched_pattern=block_pattern,
            matched_fragment=None,
            elapsed_us=record.get("total_elapsed_us", 0) // 2,  # Estimate
        )

    if channel_b is None:
        channel_b = ChannelAnalysis(
            channel_id="B",
            decision_type="Block" if block_type else "Unknown",
            decision_detail=block_pattern or block_type,
            matched_pattern=block_pattern,
            matched_fragment=None,
            elapsed_us=record.get("total_elapsed_us", 0) // 2,  # Estimate
        )

    # Extract advisory score
    advisory = record.get("advisory")
    advisory_score = None
    if isinstance(advisory, dict):
        advisory_score = advisory.get("score")

    # Build root cause prefix based on schema version
    root_cause_prefix = f"[Schema v{schema_version}] " if schema_version >= 2 else ""
    if schema_version >= 2 and (channel_a_result or channel_b_result):
        root_cause_prefix += "(Full channel data available) "

    return DisagreementDetail(
        sequence=sequence,
        timestamp=timestamp,
        input_hash=input_hash,
        input_text=input_text,
        normalised_text=normalised_text,
        channel_a=channel_a,
        channel_b=channel_b,
        advisory_score=advisory_score,
        total_elapsed_us=record.get("total_elapsed_us", 0),
        root_cause=root_cause_prefix,
    )


# ─── Rendering ────────────────────────────────────────────────────────────────

BOX_WIDTH = 72


def render_header():
    """Print tool header."""
    print()
    print("═" * BOX_WIDTH)
    print("  policy-gate Operator Review Tool")
    print("  DiagnosticDisagreement Analysis")
    print("═" * BOX_WIDTH)
    print()


def render_disagreement(detail: DisagreementDetail, verbose: bool = False):
    """Render a single DisagreementDetail in side-by-side format."""

    print(f"┌{'─' * (BOX_WIDTH - 2)}┐")
    print(f"│ {'SEQUENCE #' + str(detail.sequence):<{BOX_WIDTH - 4}} │")
    print(f"│ Timestamp:  {detail.timestamp:<{BOX_WIDTH - 16}} │")
    print(f"│ Input Hash: {detail.input_hash[:56]:<{BOX_WIDTH - 16}} │")
    print(f"├{'─' * (BOX_WIDTH - 2)}┤")

    # Input section (if available)
    if detail.input_text:
        display_input = detail.input_text[: BOX_WIDTH - 20]
        print(f"│ Input:      {display_input:<{BOX_WIDTH - 16}} │")
        if detail.normalised_text and detail.normalised_text != detail.input_text:
            display_norm = detail.normalised_text[: BOX_WIDTH - 20]
            print(f"│ Normalised: {display_norm:<{BOX_WIDTH - 16}} │")
    else:
        print(f"│ Input:      {'<not available — use --text-db>':<{BOX_WIDTH - 16}} │")

    print(f"├{'─' * (BOX_WIDTH - 2)}┤")

    # Channel comparison (side-by-side)
    col_width = (BOX_WIDTH - 7) // 2

    print(f"│ {'Channel A (FSM)':^{col_width}}│ {'Channel B (Rules)':^{col_width}}│")
    print(f"│{'─' * (col_width + 1)}┼{'─' * (col_width + 1)}│")

    # Decision
    a_decision = (
        f"{detail.channel_a.decision_type}: {detail.channel_a.decision_detail}"[
            : col_width - 2
        ]
    )
    b_decision = (
        f"{detail.channel_b.decision_type}: {detail.channel_b.decision_detail}"[
            : col_width - 2
        ]
    )
    print(f"│ {a_decision:<{col_width}}│ {b_decision:<{col_width}}│")

    # Pattern/Rule
    a_pattern = f"Pattern: {detail.channel_a.matched_pattern or 'N/A'}"[: col_width - 2]
    b_pattern = f"Rule: {detail.channel_b.matched_pattern or 'N/A'}"[: col_width - 2]
    print(f"│ {a_pattern:<{col_width}}│ {b_pattern:<{col_width}}│")

    # Elapsed
    a_time = f"Time: {detail.channel_a.elapsed_us} µs"[: col_width - 2]
    b_time = f"Time: {detail.channel_b.elapsed_us} µs"[: col_width - 2]
    print(f"│ {a_time:<{col_width}}│ {b_time:<{col_width}}│")

    print(f"├{'─' * (BOX_WIDTH - 2)}┤")

    # Root cause
    root_cause = detail.get_root_cause()
    print(f"│ ROOT CAUSE:")
    # Word wrap root cause
    words = root_cause.split()
    line = "│   "
    for word in words:
        if len(line) + len(word) + 1 > BOX_WIDTH - 2:
            print(f"{line:<{BOX_WIDTH - 2}} │")
            line = "│   " + word
        else:
            line += " " + word if line.strip() != "│" else word
    if line.strip():
        print(f"{line:<{BOX_WIDTH - 2}} │")

    print(f"├{'─' * (BOX_WIDTH - 2)}┤")

    # Recommendation
    recommendation = detail.get_recommendation()
    print(f"│ RECOMMENDATION:")
    words = recommendation.split()
    line = "│   "
    for word in words:
        if len(line) + len(word) + 1 > BOX_WIDTH - 2:
            print(f"{line:<{BOX_WIDTH - 2}} │")
            line = "│   " + word
        else:
            line += " " + word if line.strip() != "│" else word
    if line.strip():
        print(f"{line:<{BOX_WIDTH - 2}} │")

    # Advisory score
    if detail.advisory_score is not None:
        print(f"│ Advisory Score: {detail.advisory_score} (Channel C)")

    print(f"└{'─' * (BOX_WIDTH - 2)}┘")
    print()


def render_summary(disagreements: list[DisagreementDetail]):
    """Render summary statistics."""
    total = len(disagreements)
    if total == 0:
        print("  No DiagnosticDisagreement events found.")
        return

    # Count by root cause pattern
    a_pass_b_block = sum(
        1
        for d in disagreements
        if d.channel_a.decision_type == "Pass" and d.channel_b.decision_type == "Block"
    )
    a_block_b_pass = sum(
        1
        for d in disagreements
        if d.channel_a.decision_type == "Block" and d.channel_b.decision_type == "Pass"
    )
    other = total - a_pass_b_block - a_block_b_pass

    # Count with advisory disagreement
    with_advisory = sum(1 for d in disagreements if d.advisory_score is not None)

    # Count with input text available
    with_text = sum(1 for d in disagreements if d.input_text is not None)

    print("─" * BOX_WIDTH)
    print(f"  SUMMARY: {total} DiagnosticDisagreement events")
    print("─" * BOX_WIDTH)
    print(
        f"  Channel A=Pass, B=Block: {a_pass_b_block:>5}  ({a_pass_b_block / total * 100:.1f}%)"
    )
    print(
        f"  Channel A=Block, B=Pass: {a_block_b_pass:>5}  ({a_block_b_pass / total * 100:.1f}%)"
    )
    print(f"  Other:                   {other:>5}  ({other / total * 100:.1f}%)")
    print(
        f"  With Advisory Score:     {with_advisory:>5}  ({with_advisory / total * 100:.1f}%)"
    )
    print(
        f"  With Input Text:         {with_text:>5}  ({with_text / total * 100:.1f}%)"
    )
    print()


# ─── Interactive Mode ─────────────────────────────────────────────────────────


def run_interactive(disagreements: list[DisagreementDetail], actions_log: list[dict]):
    """Interactive review mode — walk through each disagreement."""

    print("INTERACTIVE MODE: Review each DiagnosticDisagreement event.")
    print(
        "Commands: [a]cknowledge, [p]attern-add, [P]attern-add-auto, [r]ule-adjust, [f]alse-positive, [t]rue-positive, [d]efer, [s]kip, [q]uit"
    )
    print()

    for i, detail in enumerate(disagreements):
        print(f"\n{'━' * BOX_WIDTH}")
        print(f"  Reviewing {i + 1}/{len(disagreements)}")
        print(f"{'━' * BOX_WIDTH}")

        render_disagreement(detail, verbose=True)

        while True:
            action = input("Action [a/p/P/r/f/t/d/s/q]: ").strip().lower()

            if action in ("q", "quit", "exit"):
                print("\n  Saving actions and exiting...")
                return True  # Signal to save and exit

            elif action in ("s", "skip"):
                detail.operator_action = OperatorAction.DEFER
                detail.operator_notes = "Skipped by operator"
                break

            elif action in ("a", "acknowledge"):
                detail.operator_action = OperatorAction.ACKNOWLEDGE
                detail.operator_notes = input("Notes (optional): ").strip()
                break

            elif action in ("p", "pattern-add"):
                # Manual pattern add (existing behavior)
                detail.operator_action = OperatorAction.ADD_PATTERN
                detail.operator_notes = input("Pattern to add: ").strip()
                break

            elif action in ("P", "pattern-add-auto"):
                # Auto-generate pattern from the disagreement
                detail.operator_action = OperatorAction.ADD_PATTERN_AUTO
                
                # Extract problematic text
                problem_text = extract_problematic_text(detail)
                
                if problem_text:
                    # Generate regex and TOML patch
                    regex_pattern = generate_regex_from_text(problem_text)
                    toml_patch = generate_toml_patch(
                        regex_pattern, 
                        f"Operator-Review: FP #{detail.sequence}",
                        detail.sequence
                    )
                    
                    print(f"\n  AUTO-GENERATED PATTERN:")
                    print(f"  Input Text:   {problem_text[:60]}")
                    print(f"  Regex:        {regex_pattern[:60]}")
                    print(f"  TOML Patch:")
                    print(toml_patch)
                    
                    # Ask for confirmation or editing
                    confirm = input("\n  Accept pattern? [y]es / [e]dit / [n]o: ").strip().lower()
                    
                    if confirm == "y" or confirm == "":
                        detail.operator_notes = f"auto:{regex_pattern}"
                        print(f"  Pattern accepted")
                        
                        # Auto-write to firewall.toml
                        write_ok = write_toml_patch(
                            regex_pattern,
                            f"Operator-Review: FP #{detail.sequence}",
                            detail.sequence
                        )
                        if write_ok:
                            print(f"  [AUTO] Pattern written to firewall.toml")
                        else:
                            print(f"  [WARN] Failed to write to firewall.toml - pattern still recorded")
                    elif confirm == "e":
                        # Allow manual editing
                        new_pattern = input("  Enter custom pattern: ").strip()
                        detail.operator_notes = f"manual:{new_pattern}"
                        
                        # Write custom pattern to TOML
                        write_ok = write_toml_patch(
                            new_pattern,
                            f"Operator-Review: FP #{detail.sequence}",
                            detail.sequence
                        )
                        if write_ok:
                            print(f"  [AUTO] Custom pattern written to firewall.toml")
                    else:
                        # User declined - skip this action
                        print("  Pattern rejected, action cancelled")
                        continue
                else:
                    print("  [WARN] Could not extract input text for auto-generation")
                    print("  Falling back to manual pattern entry")
                    detail.operator_action = OperatorAction.ADD_PATTERN
                    detail.operator_notes = input("Pattern to add: ").strip()
                break

            elif action in ("r", "rule-adjust"):
                detail.operator_action = OperatorAction.ADJUST_RULE
                detail.operator_notes = input("Rule adjustment: ").strip()
                break

            elif action in ("f", "false-positive"):
                detail.operator_action = OperatorAction.FALSE_POSITIVE
                detail.operator_notes = input("Notes: ").strip()
                break

            elif action in ("t", "true-positive"):
                detail.operator_action = OperatorAction.TRUE_POSITIVE
                detail.operator_notes = input("Notes (optional): ").strip()
                break

            elif action in ("d", "defer"):
                detail.operator_action = OperatorAction.DEFER
                detail.operator_notes = input("Reason for deferral: ").strip()
                break

            else:
                print("  Unknown command. Use: a/p/P/r/f/t/d/s/q")

        # Record action
        actions_log.append(
            {
                "sequence": detail.sequence,
                "action": detail.operator_action.value
                if detail.operator_action
                else "none",
                "notes": detail.operator_notes,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )

        print(f"  Recorded: {detail.operator_action.value}")

    return False  # Completed all


# ─── Export ───────────────────────────────────────────────────────────────────


def export_findings(disagreements: list[DisagreementDetail], output_path: str):
    """Export findings to JSON for further analysis."""
    findings = []
    for d in disagreements:
        findings.append(
            {
                "sequence": d.sequence,
                "timestamp": d.timestamp,
                "input_hash": d.input_hash,
                "channel_a_decision": d.channel_a.decision_type,
                "channel_a_detail": d.channel_a.decision_detail,
                "channel_a_pattern": d.channel_a.matched_pattern,
                "channel_b_decision": d.channel_b.decision_type,
                "channel_b_detail": d.channel_b.decision_detail,
                "channel_b_pattern": d.channel_b.matched_pattern,
                "advisory_score": d.advisory_score,
                "root_cause": d.get_root_cause(),
                "recommendation": d.get_recommendation(),
                "operator_action": d.operator_action.value
                if d.operator_action
                else None,
                "operator_notes": d.operator_notes,
            }
        )

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2)

    print(f"  Exported {len(findings)} findings to: {output_path}")


def save_actions_log(actions_log: list[dict], path: str):
    """Save operator actions to JSON Lines file."""
    with open(path, "w", encoding="utf-8") as f:
        for action in actions_log:
            f.write(json.dumps(action) + "\n")
    print(f"  Saved {len(actions_log)} operator actions to: {path}")


# ─── Main ─────────────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(
        description="Operator Review Tool for DiagnosticDisagreement events.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Review all DD events
  python operator_review.py --input audit.ndjson

  # Interactive review with input text database
  python operator_review.py --input audit.ndjson --interactive --text-db inputs.db

  # Export findings for rule tuning
  python operator_review.py --input audit.ndjson --export findings.json
        """,
    )
    parser.add_argument(
        "--input", "-i", required=True, help="Path to NDJSON audit log file"
    )
    parser.add_argument(
        "--sequence", "-s", type=int, help="Review specific sequence number only"
    )
    parser.add_argument(
        "--interactive", action="store_true", help="Interactive review mode"
    )
    parser.add_argument("--text-db", help="Path to SQLite database with input texts")
    parser.add_argument("--export", "-e", help="Export findings to JSON file")
    parser.add_argument(
        "--actions-log",
        default="operator_actions.jsonl",
        help="Path to save operator actions (default: operator_actions.jsonl)",
    )
    parser.add_argument(
        "--summary-only", action="store_true", help="Show summary only, no details"
    )
    args = parser.parse_args()

    # Validate input
    if not Path(args.input).exists():
        print(f"Error: Input file not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    # Load data
    render_header()
    print(f"  Loading audit log: {args.input}")
    records = load_audit_log(args.input)
    print(f"  Loaded {len(records)} records")

    # Load text database if provided
    text_db = {}
    if args.text_db:
        print(f"  Loading text database: {args.text_db}")
        text_db = load_text_database(args.text_db)
        print(f"  Loaded {len(text_db)} input texts")

    # Filter for DiagnosticDisagreement
    dd_records = [
        r for r in records if r.get("verdict_kind") == "DiagnosticDisagreement"
    ]
    print(f"  Found {len(dd_records)} DiagnosticDisagreement events")

    if not dd_records:
        print("\n  No DiagnosticDisagreement events to review.")
        sys.exit(2)

    # Filter by sequence if requested
    if args.sequence is not None:
        dd_records = [r for r in dd_records if r.get("sequence") == args.sequence]
        if not dd_records:
            print(f"\n  No DiagnosticDisagreement event with sequence {args.sequence}")
            sys.exit(2)

    # Analyze
    print("  Analyzing disagreements...")
    disagreements = []
    for record in dd_records:
        detail = analyze_disagreement(record, text_db)
        if detail:
            disagreements.append(detail)

    print(f"  Analyzed {len(disagreements)} events")

    # Summary
    render_summary(disagreements)

    # Exit if summary only
    if args.summary_only:
        sys.exit(0)

    # Detailed view
    if not args.interactive:
        for detail in disagreements:
            render_disagreement(detail, verbose=True)

    # Interactive mode
    actions_log = []
    if args.interactive:
        quit_early = run_interactive(disagreements, actions_log)
        if actions_log:
            save_actions_log(actions_log, args.actions_log)

    # Export
    if args.export:
        export_findings(disagreements, args.export)

    # Exit code based on actions
    if any(
        d.operator_action
        in (
            OperatorAction.ADD_PATTERN,
            OperatorAction.ADD_PATTERN_AUTO,
            OperatorAction.ADJUST_RULE,
            OperatorAction.FALSE_POSITIVE,
        )
        for d in disagreements
        if d.operator_action
    ):
        sys.exit(3)  # Action required
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
