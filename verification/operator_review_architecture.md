# Operator Review Tool — Architecture Notes

## Overview

`operator_review.py` provides side-by-side analysis of DiagnosticDisagreement events,
enabling operators to make informed decisions about rule engine tuning.

## Implementation Status: ✅ COMPLETE

**Option A has been fully implemented.** The AuditEntry schema now includes:

```rust
pub struct AuditEntry {
    // ... existing fields ...
    
    /// Schema version for forward compatibility. Current: 2.
    /// v1: basic audit (input_hash only)
    /// v2: full channel results + input text for operator review
    pub schema_version: u32,
    
    /// Full Channel A result for side-by-side operator review.
    /// Only populated when audit.store_channel_results = true in config.
    pub channel_a_result: Option<ChannelResult>,
    
    /// Full Channel B result for side-by-side operator review.
    /// Only populated when audit.store_channel_results = true in config.
    pub channel_b_result: Option<ChannelResult>,
    
    /// Original input text for operator review.
    /// Only populated when audit.store_input_text = true in config.
    /// WARNING: May contain sensitive data — use only in non-production environments.
    pub input_text: Option<String>,
}
```

## Configuration

Two new configuration flags control what data is stored:

```rust
pub struct AuditConfig {
    /// Store full ChannelResult for Channel A and B in audit entry.
    /// Enables detailed side-by-side operator review.
    /// Default: false (for production privacy).
    pub store_channel_results: bool,
    
    /// Store original input text in audit entry.
    /// WARNING: May contain sensitive data — use only in non-production.
    /// Default: false.
    pub store_input_text: bool,
}
```

## Usage

### Basic evaluation (default, production-safe)
```rust
let verdict = evaluate(input, sequence);
// AuditEntry will have schema_version: 2, but channel_results and input_text will be None
```

### Full audit for operator review
```rust
let config = AuditConfig {
    store_channel_results: true,
    store_input_text: true,
};
let verdict = evaluate_with_config(input, sequence, &config);
// AuditEntry will have full channel results and input text
```

## Operator Review Tool Integration

The `operator_review.py` tool already supports schema v2:

```bash
# Review with full channel data
python verification/operator_review.py --input audit.ndjson

# Review with input text database (fallback for v1 logs)
python verification/operator_review.py --input audit.ndjson --text-db inputs.db
```

When v2 audit entries are present, the tool displays:
- **Channel A (FSM)**: Decision, Pattern ID, Matched Intent
- **Channel B (Rules)**: Decision, Rule ID, Block Reason
- **Input Text**: Original and normalised (if stored)
- **Root Cause Analysis**: Automatic detection of disagreement patterns
- **Recommendations**: Suggested operator actions

## Migration Path

### For existing v1 audit logs
- Use `--text-db` flag to provide input texts separately
- Or re-evaluate with `store_channel_results: true` to generate v2 logs

### For new deployments
- Enable `store_channel_results: true` in non-production environments
- Enable `store_input_text: true` only in development/testing (privacy concern)
- Production: Keep defaults (false) for privacy, use `--text-db` for reviews

## Safety Properties

- Schema version bump (v1 → v2) is backward compatible
- Optional fields ensure no breaking changes for existing consumers
- Input text storage is opt-in with clear privacy warnings
- Channel results storage is opt-in for performance/privacy balance

## Auto-Regex Generation (ADD_PATTERN_AUTO)

**Status: ✅ IMPLEMENTED**

The operator review tool supports automatic regex generation for false positive remediation:

### Operator Actions

| Action | Shortcut | Description |
|--------|----------|-------------|
| `ADD_PATTERN` | `p` | Manual pattern entry — operator types regex directly |
| `ADD_PATTERN_AUTO` | `P` | Auto-generate regex from problematic input text |

### Regex Generation Algorithm

The `generate_regex_from_text()` function in `operator_review.py` implements:

1. **Basic escaping**: Special regex characters escaped via `re.escape()`
2. **Leetspeak detection**: Maps `0→[0o]`, `1→[1li]`, `3→[3e]`, `@→[@a]`, `$→[$s]`, etc.
3. **Mixed case handling**: Adds `(?i)` flag for case-insensitive matching
4. **TOML patch generation**: Creates ready-to-use `[[intent_patterns.allowlist]]` snippet
5. **Auto-Write to firewall.toml**: `write_toml_patch()` writes directly to firewall.toml after operator confirmation

### Auto-Write Function

**`write_toml_patch()` (operator_review.py:189)** handles automatic file operations:

1. Checks if `firewall.toml` exists in the workdir
2. If not present, copies `firewall.example.toml` as template
3. Appends the generated pattern to the `[intent_patterns.allowlist]` section
4. Pattern is immediately active after confirmation — no manual editing required

This enables a fully automated workflow: operator identifies FP → presses `P` → confirms → pattern auto-written to config.

### Interactive Usage

```bash
# Start interactive review
python verification/operator_review.py --input audit.ndjson --interactive

# In interactive mode:
# Press 'P' to auto-generate pattern from current disagreement
# The tool extracts problematic text, generates regex, shows preview
# Operator can accept (y), edit (e), or reject (n)
```

### Example Output

```
  AUTO-GENERATED PATTERN:
  Input Text:   Write a program that helps people with their da1ly tasks
  Regex:        (?i)Write a program that helps people with their [da1l]y tasks
  TOML Patch:
  [[intent_patterns.allowlist]]
  pattern = "(?i)Write a program that helps people with their [da1l]y tasks"
  reason = "Operator-Review: FP #42"
```

### Safety Considerations

- Auto-generated patterns are validated through operator review (not auto-deployed)
- Pattern must be manually reviewed and confirmed before being added to allowlist
- Z3 proofs remain unchanged — pattern is added to existing intent pattern set

## Integration Checklist

- [x] Add `channel_results` field to `types.rs::AuditEntry`
- [x] Update `lib.rs` to populate channel results in audit entry
- [x] Update schema_version to 2
- [x] Add `AuditConfig` for opt-in control
- [x] Add `evaluate_with_config()` function
- [x] Update `operator_review.py` to parse full channel results (already v2-ready)
- [x] Add auto-regex generation (`generate_regex_from_text`)
- [x] Add `ADD_PATTERN_AUTO` operator action
- [ ] Update Z3 proofs if audit entry changes affect safety properties
