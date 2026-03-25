#!/usr/bin/env python3
"""
disagreement_analytics.py — Audit log analysis for DiagnosticDisagreement events.

Reads NDJSON audit entries produced by firewall-core and reports:
   - Differentiate DiagnosticAgreement (DA) vs DiagnosticDisagreement (DD)
   - Overall verdict distribution
   - DiagnosticAgreement rate (Safety Health Metric)
   - DiagnosticDisagreement rate (Critical Divergence)
   - Sliding-window analysis for "Low-and-Slow" probing

Usage:
    python verification/disagreement_analytics.py --input audit.ndjson
    python verification/disagreement_analytics.py --input audit.ndjson --csv report.csv
    python verification/disagreement_analytics.py --input audit.ndjson --trend hourly
    python verification/disagreement_analytics.py --input audit.ndjson --window 500 --follow

Expected NDJSON record format (one JSON object per line):
    {
        "schema_version": 1,
        "sequence": 42,
        "verdict_kind": "DiagnosticDisagreement",
        "block_reason": {"type": "ForbiddenPattern", "pattern_id": "RE-003-HIJACK"},
        "input_hash": "abc123...",
        "advisory": {"type": "Disagreement", "score": 4, "heuristic_version": 2},
        "total_elapsed_us": 312,
        "ingested_at_ns": 1700000000000000000,
        "decided_at_ns":  1700000000000312000
    }

No external dependencies — stdlib only.
"""

import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path


# ─── Loading ──────────────────────────────────────────────────────────────────

def load_records(path: str) -> list[dict]:
    records = []
    errors: int = 0
    with open(path, encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as e:
                print(f"  [WARN] Line {lineno}: JSON parse error — {e}", file=sys.stderr)
                errors += 1
    if errors:
        print(f"  [WARN] {errors} lines skipped due to parse errors.", file=sys.stderr)
    return records


# ─── Analysis ─────────────────────────────────────────────────────────────────

def analyse(records: list[dict]) -> dict:
    total = len(records)
    if total == 0:
        return {"total": 0}

    verdict_counts: Counter = Counter()
    block_reason_counts: Counter = Counter()
    advisory_counts: Counter = Counter()
    elapsed_by_verdict: dict[str, list[int]] = defaultdict(list)

    da_records = []
    dd_records = []

    for r in records:
        vk = r.get("verdict_kind", "Unknown")
        verdict_counts[vk] += 1
        elapsed_by_verdict[vk].append(r.get("total_elapsed_us", 0))

        br = r.get("block_reason")
        if br:
            if isinstance(br, dict):
                br_type = br.get("type", "Unknown")
                br_id = br.get("pattern_id") or br.get("detail") or br_type
                block_reason_counts[f"{br_type}: {br_id}"] += 1
            else:
                block_reason_counts[str(br)] += 1

        advisory = r.get("advisory")
        if isinstance(advisory, dict):
            advisory_counts[advisory.get("type", "Unknown")] += 1
        elif isinstance(advisory, str):
            advisory_counts[advisory] += 1
        else:
            advisory_counts["None"] += 1

        if vk == "DiagnosticDisagreement":
            dd_records.append(r)
        elif vk == "DiagnosticAgreement":
            da_records.append(r)

    # Latency stats
    def latency_stats(values):
        if not values:
            return {"min": 0, "max": 0, "avg": 0, "p95": 0}
        s = sorted(values)
        p95_idx = int(len(s) * 0.95)
        return {
            "min": s[0],
            "max": s[-1],
            "avg": int(sum(s) / len(s)),
            "p95": s[p95_idx],
        }

    all_elapsed = [r.get("total_elapsed_us", 0) for r in records]

    # Time-series bins (SA-061: Trend Analysis)
    bins: dict[str, list[dict]] = defaultdict(list)
    for r in records:
        ns = r.get("decided_at_ns")
        if ns:
            # Simple flooring to hour/day/minute for binning
            ts_sec = ns // 1_000_000_000
            bins[str(ts_sec)].append(r) # Just a placeholder, main logic in print_trend

    return {
        "total": total,
        "verdict_counts": dict(verdict_counts),
        "block_reason_top10": block_reason_counts.most_common(10),
        "advisory_counts": dict(advisory_counts),
        "da_count": len(da_records),
        "da_rate_pct": (len(da_records) / total * 100) if total > 0 else 0.0,
        "dd_count": len(dd_records),
        "dd_rate_pct": (len(dd_records) / total * 100) if total > 0 else 0.0,
        "latency_overall": latency_stats(all_elapsed),
        "latency_by_verdict": {vk: latency_stats(vals) for vk, vals in elapsed_by_verdict.items()},
        "records": records, 
    }


# ─── Reporting ────────────────────────────────────────────────────────────────

COL_W = 60

def banner(title: str):
    print(f"\n{'═' * COL_W}")
    print(f"  {title}")
    print(f"{'═' * COL_W}")

def section(title: str):
    print(f"\n{'─' * COL_W}")
    print(f"  {title}")
    print(f"{'─' * COL_W}")

def print_report(data: dict):
    if data["total"] == 0:
        banner("policy-gate Audit Analytics")
        print("  No records found.")
        return

    banner("policy-gate Audit Analytics")
    print(f"  Total audit entries analysed: {data['total']:,}")

    section("Verdict Distribution")
    for vk, count in sorted(data["verdict_counts"].items(), key=lambda x: -x[1]):
        pct = count / data["total"] * 100
        bar = "█" * int(pct / 2)
        print(f"  {vk:<30} {count:>6,}  ({pct:5.1f}%)  {bar}")

    section(f"Safety Health Metrics [DA: {data['da_rate_pct']:.2f}% | DD: {data['dd_rate_pct']:.4f}%]")
    
    # DA Analysis (Agreement but intent mismatch)
    print(f"  [DA] DiagnosticAgreement : {data['da_count']:,} ({data['da_rate_pct']:.2f}%)")
    if data["da_rate_pct"] > 5.0:
        print("       !! ALERT: High DA rate (>5%). Potential adversarial probing.")
    elif data["da_rate_pct"] > 1.0:
        print("       + WARNING: Sustained DA rate (>1%). Review intent patterns.")
    else:
        print("       . Healthy alignment (0-1%).")
        
    print()

    # DD Analysis (Critical logic divergence)
    print(f"  [DD] DiagnosticDisagreement: {data['dd_count']:,} ({data['dd_rate_pct']:.4f}%)")
    if data["dd_count"] == 0:
        print("       . Channels fully logic-aligned.")
    else:
        print("       CRITICAL: Manual operator review required within 24h (SR-007).")

    section("Top Block Reasons (all Block + DiagnosticDisagreement verdicts)")
    if not data["block_reason_top10"]:
        print("  No block reasons recorded.")
    else:
        for rank, (reason, count) in enumerate(data["block_reason_top10"], 1):
            print(f"  {rank:>2}. {reason:<46} {count:>6,}")

    section("Advisory Channel C Distribution")
    for tag, count in sorted(data["advisory_counts"].items(), key=lambda x: -x[1]):
        pct = count / data["total"] * 100
        print(f"  {tag:<30} {count:>6,}  ({pct:5.1f}%)")

    section("Latency Summary (µs)")
    hdr = f"  {'Verdict':<30} {'min':>8} {'avg':>8} {'p95':>8} {'max':>8}"
    print(hdr)
    print(f"  {'─' * (len(hdr) - 2)}")
    overall = data["latency_overall"]
    print(f"  {'[ALL]':<30} {overall['min']:>8,} {overall['avg']:>8,} {overall['p95']:>8,} {overall['max']:>8,}")
    for vk, stats in sorted(data["latency_by_verdict"].items()):
        print(f"  {vk:<30} {stats['min']:>8,} {stats['avg']:>8,} {stats['p95']:>8,} {stats['max']:>8,}")

    print(f"\n{'═' * COL_W}\n")


def print_trend(data: dict, interval: str):
    banner(f"Detection Trends ({interval})")
    records = data["records"]
    if not records:
        return

    # Bin records by time
    # Interval modes: 'hourly' (YYYY-MM-DD HH), 'daily' (YYYY-MM-DD), 'minute'
    import datetime

    bins = defaultdict(list)
    for r in records:
        ns = r.get("decided_at_ns")
        if not ns: continue
        dt = datetime.datetime.fromtimestamp(ns / 1_000_000_000, tz=datetime.timezone.utc)
        if interval == "hourly":
            key = dt.strftime("%Y-%m-%d %H:00")
        elif interval == "minute":
            key = dt.strftime("%Y-%m-%d %H:%M")
        else: # daily
            key = dt.strftime("%Y-%m-%d")
        bins[key].append(r)

    print(f"  {'Time Interval':<20} | {'Total':>6} | {'DA %':>6} | {'DD %':>6}")
    print(f"  {'-'*20} | {'-'*6} | {'-'*6} | {'-'*6}")

    for key in sorted(bins.keys()):
        window = bins[key]
        total = len(window)
        da = sum(1 for r in window if r.get("verdict_kind") == "DiagnosticAgreement")
        dd = sum(1 for r in window if r.get("verdict_kind") == "DiagnosticDisagreement")
        da_pct = (da / total * 100) if total > 0 else 0
        dd_pct = (dd / total * 100) if total > 0 else 0

        # Sparkline-ish indicator for DA
        spark = "!" if da_pct > 5 else "+" if da_pct > 1 else "."
        print(f"  {key:<20} | {total:>6,} | {da_pct:>5.1f}% | {dd_pct:>5.1f}%  {spark}")

    print(f"\n  [Legend] DA (DiagnosticAgreement), DD (DiagnosticDisagreement)")
    print(f"           Thresholds: >1% review (+), >5% alert (!)")


def run_follow(path: str, window_size: int):
    import time
    from collections import deque
    
    banner(f"Real-time Monitoring (SA-051) - Window N={window_size}")
    print(f"  Watching: {path}")
    print(f"  {'Timestamp':<25} | {'Verdict':<20} | {'DA% (Rolling)':>12}")
    print(f"  {'-'*25} | {'-'*20} | {'-'*12}")

    buffer = deque(maxlen=window_size)
    
    # Pre-fill buffer with existing records
    records = load_records(path)
    for r in records:
        buffer.append(r)
    
    def report_current():
        if not buffer: return
        da = sum(1 for r in buffer if r.get("verdict_kind") == "DiagnosticAgreement")
        da_pct = (da / len(buffer) * 100)
        spark = "!" if da_pct > 5 else "+" if da_pct > 1 else "."
        # Only show last record's time for context
        last_dt = "Now"
        ns = buffer[-1].get("decided_at_ns")
        if ns:
            import datetime
            dt = datetime.datetime.fromtimestamp(ns / 1_000_000_000, tz=datetime.timezone.utc)
            last_dt = dt.strftime("%Y-%m-%d %H:%M:%S")
        
        vk = buffer[-1].get("verdict_kind", "Unknown")
        print(f"  {last_dt:<25} | {vk:<20} | {da_pct:>11.1f}%  {spark}")
        
        # Real-time exit/alert signal (stderr for side-channel alerting)
        if da_pct > 5.0:
            print(f">>> [ALERT] SA-051 Violation: Rolling DA Rate {da_pct:.1f}% exceeds 5% threshold!", file=sys.stderr)

    report_current()

    # Tail implementation
    with open(path, "r", encoding="utf-8") as f:
        # Go to end
        f.seek(0, 2)
        try:
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.5)
                    continue
                
                try:
                    r = json.loads(line)
                    buffer.append(r)
                    report_current()
                except json.JSONDecodeError:
                    continue
        except KeyboardInterrupt:
            print("\n  Monitoring stopped.")


def run_similarity_analysis(records: list[dict], threshold: float, window_size: int):
    """
    SA-062: Similarity-based probing detection.
    Clusters prompts using Levenshtein distance to detect variations of the same attack.
    """
    banner(f"Similarity-based Probing Detection (Threshold={threshold}, Window={window_size})")
    if not records:
        print("  No records to analyse.")
        return

    # Helper for Levenshtein distance
    def levenshtein(s1, s2):
        if len(s1) < len(s2):
            return levenshtein(s2, s1)
        if not s2:
            return len(s1)
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        return previous_row[-1]

    # Process records in windows
    clusters = []
    
    # Simple clustering: if a prompt is similar to an existing cluster representative, add it.
    # Otherwise, start a new cluster.
    for i in range(len(records)):
        r = records[i]
        text = r.get("input_hash", "") # Use hash if text not in audit, or hypothetical 'input_text'
        # In a real system, we'd want the raw text. For this simulation/CLI, 
        # let's assume 'input_text' might be there or use 'input_hash' as a proxy 
        # (though hash similarity != text similarity).
        # To make it meaningful, we SHOULD have the text. 
        # Let's check for 'input_text' or fallback to 'input_hash'.
        content = r.get("input_text") or r.get("input_hash", "")
        if not content: continue
        
        found = False
        for cluster in clusters:
            representative = cluster["rep"]
            dist = levenshtein(content, representative)
            max_len = max(len(content), len(representative))
            similarity = 1.0 - (dist / max_len) if max_len > 0 else 1.0
            
            if similarity >= threshold:
                cluster["count"] += 1
                cluster["indices"].append(i)
                found = True
                break
        
        if not found:
            clusters.append({"rep": content, "count": 1, "indices": [i]})

    # Report clusters with > 1 members
    suspicious = [c for c in clusters if c["count"] > 1]
    suspicious.sort(key=lambda x: -x["count"])

    if not suspicious:
        print("  No suspicious similarity clusters detected.")
    else:
        print(f"  Detected {len(suspicious)} suspicious clusters:\n")
        print(f"  {'Count':>6} | {'Similarity Cluster Representative (truncated)':<45}")
        print(f"  {'-'*6} | {'-'*45}")
        for c in suspicious[:10]:
            rep = c["rep"]
            if len(rep) > 42: rep = rep[:39] + "..."
            print(f"  {c['count']:>6} | {rep:<45}")
            if c["count"] > 5:
                print(f"       !! ALERT: High-density cluster detected (count={c['count']}). Potential 'low-and-slow' probing.")

    print(f"\n  [Note] Analysis performed on all {len(records)} records.")


def print_window(data: dict, size: int):
    banner(f"Sliding Window Analysis (N={size})")
    records = data["records"]
    if not records:
        return

    print(f"  {'Window Range':<20} | {'DA %':>6} | {'DD %':>6}")
    print(f"  {'-'*20} | {'-'*6} | {'-'*6}")

    # Slide window over records
    for i in range(len(records)):
        if i < size - 1: continue
        window = records[i - size + 1 : i + 1]
        
        # We only print occasional samples to avoid spamming the CLI
        # but we check every window for alerts.
        da = sum(1 for r in window if r.get("verdict_kind") == "DiagnosticAgreement")
        dd = sum(1 for r in window if r.get("verdict_kind") == "DiagnosticDisagreement")
        da_pct = (da / size * 100)
        dd_pct = (dd / size * 100)
        
        if da_pct > 5.0 or dd_pct > 0.1 or (i % (size // 2 or 1) == 0) or (i == len(records)-1):
            key = f"Req {i-size+1:04} - {i:04}"
            spark = "!" if da_pct > 5 else "+" if da_pct > 1 else "."
            print(f"  {key:<20} | {da_pct:>5.1f}% | {dd_pct:>5.1f}%  {spark}")

    print(f"\n  [Legend] DA (DiagnosticAgreement), DD (DiagnosticDisagreement)")
    print(f"           Thresholds: >1% review (+), >5% alert (!)")


def write_csv(data: dict, path: str):
    rows = []

    for vk, count in data["verdict_counts"].items():
        rows.append({"category": "verdict", "key": vk, "count": count,
                     "rate_pct": round(count / data["total"] * 100, 2)})

    for reason, count in data["block_reason_top10"]:
        rows.append({"category": "block_reason", "key": reason, "count": count, "rate_pct": ""})

    for tag, count in data["advisory_counts"].items():
        rows.append({"category": "advisory", "key": tag, "count": count,
                     "rate_pct": round(count / data["total"] * 100, 2)})

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["category", "key", "count", "rate_pct"])
        writer.writeheader()
        writer.writerows(rows)

    print(f"  CSV written to: {path}")


# ─── Entry point ──────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Analyse policy-gate NDJSON audit logs for DiagnosticDisagreement events."
    )
    parser.add_argument("--input", "-i", required=True, help="Path to NDJSON audit log file")
    parser.add_argument("--csv", "-o", help="Optional: write summary to CSV file")
    parser.add_argument("--trend", choices=["hourly", "daily", "minute"], help="Plot trends over time")
    parser.add_argument("--window", type=int, default=100, help="Sliding-window analysis (last N requests)")
    parser.add_argument("--follow", action="store_true", help="Monitor audit log in real-time (SA-051)")
    parser.add_argument("--similarity", type=float, default=0.85, help="Alert on clusters with similarity >= threshold (default 0.85)")
    args = parser.parse_args()

    if not Path(args.input).exists():
        print(f"Error: input file not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    records = load_records(args.input)
    data = analyse(records)
    print_report(data)

    if args.trend:
        print_trend(data, args.trend)

    if args.follow:
        run_follow(args.input, args.window)
        return

    if args.window and not args.follow:
        print_window(data, args.window)

    if args.csv:
        write_csv(data, args.csv)

    if args.similarity:
        run_similarity_analysis(records, args.similarity, args.window)

    # Exit non-zero if agreement rate exceeds 1% (operator signal)
    if data.get("da_rate_pct", 0.0) > 1.0:
        print(f"\n  [SIGNAL] DA rate {data['da_rate_pct']:.2f}% exceeds 1% calibration threshold. (Exit 2)")
        sys.exit(2)
    
    if data.get("dd_count", 0) > 0:
        print(f"\n  [SIGNAL] Critical DiagnosticDisagreement detected. (Exit 3)")
        sys.exit(3)

if __name__ == "__main__":
    main()
