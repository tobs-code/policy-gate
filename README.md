# policy-gate

[![CI](https://github.com/tobs-code/policy-gate/actions/workflows/ci.yml/badge.svg)](https://github.com/tobs-code/policy-gate/actions)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org)
[![Safety](https://img.shields.io/badge/safety-experimental-yellow.svg)](SAFETY_MANUAL.md)

Deterministic firewall for LLM applications, agents, and AI gateways.

Instead of trying to guess whether a prompt is dangerous, `policy-gate` only permits explicitly allowlisted intents. Unknown, ambiguous, or policy-violating inputs fail closed.

It is designed for teams that want predictable enforcement, auditable decisions, and a narrow control boundary around model access.

**Status:** Experimental — under active development. Not certified for production use.  
**Note:** This project borrows architectural ideas from functional safety engineering, but it is not an IEC 61508 implementation and makes no certification or compliance claims.

## At a glance

- deterministic allowlist-first enforcement
- fail-closed behavior on ambiguity, disagreement, or fault
- auditable PASS/BLOCK outcomes
- advisory heuristics and semantic analysis kept outside the safety path
- optional session-aware analysis for multi-turn escalation patterns
- Rust core with Node, Python, and WASM targets

## Best fit

`policy-gate` is a good fit when only a small, well-defined set of user intents should ever reach a model or downstream toolchain.

Typical examples:

- fronting an agent that can call tools or execute multi-step workflows
- enforcing tenant- or profile-specific prompt policies
- validating model output for prompt leakage, credential leakage, or PII
- creating a reviewable PASS/BLOCK layer in front of LLM APIs
- detecting multi-turn escalation attempts across conversation turns

It is a weaker fit for broad, open-ended chatbot moderation or any workflow where the allowed intent space is large and fluid.

## Why this approach

Most AI guardrails are probabilistic classifiers. They can be useful, but they are often hard to reason about, hard to audit, and difficult to bound in high-control environments.

`policy-gate` takes a narrower approach:

- allow only known-good intent shapes
- block unknown or ambiguous requests by default
- keep the safety path deterministic
- treat heuristic and semantic analysis as advisory, not authoritative
- produce audit records for every decision

For narrow workflows, it is often better to make unsafe requests unrepresentable than to estimate whether they look risky.

## Guarantees and non-goals

What `policy-gate` aims to provide:

- deterministic PASS/BLOCK behavior on the core safety path
- fail-closed handling for ambiguity, disagreement, and internal faults
- reviewable audit output for each decision
- optional advisory analysis that never overrides the core verdict

What it does not aim to be:

- a general-purpose conversational safety layer
- a replacement for policy design, threat modeling, or human review
- a certification-grade safety system
- a claim of IEC 61508 compliance

## Quick example

### TypeScript

```ts
import { Firewall } from "policy-gate";

const firewall = await Firewall.create({
  onAudit: async (entry) => {
    await db.audit.insert(entry);
  },
});

const verdict = await firewall.evaluate("What is the capital of France?");

if (!verdict.isPass) {
  throw new Error(`Blocked: ${verdict.blockReason}`);
}

// safe to forward to the model
```

### Session-aware evaluation

```ts
import { Firewall } from "policy-gate";

const firewall = await Firewall.create({
  onAudit: async (entry) => {
    await db.audit.insert(entry);
  },
});

// Optional session-aware evaluation for multi-turn conversations
const sessionId = "user-123";
const verdict = await firewall.evaluateWithSession(
  sessionId,
  "How can I bypass security restrictions?"
);

if (!verdict.isPass) {
  console.log(`Blocked: ${verdict.blockReason}`);
  console.log(`Session risk: ${verdict.sessionAnalysis?.riskLevel}`);
  console.log(`Escalation score: ${verdict.sessionAnalysis?.escalationScore}`);
}

// Session statistics
const stats = firewall.getSessionStats();
console.log(`Active sessions: ${stats.activeSessions}`);
console.log(`High-risk sessions: ${stats.highRiskSessions}`);
```

### Python

```python
import policy_gate

policy_gate.init()

verdict = policy_gate.evaluate_raw("What is the capital of France?")

if not verdict["is_pass"]:
    raise RuntimeError(f"Blocked: {verdict['block_reason']}")
```

## How it works

At a high level, the firewall:

1. normalizes and hardens the input before policy evaluation
2. evaluates it through independent deterministic channels
3. votes fail-closed on disagreements or faults
4. records an audit entry for review and analytics
5. can also validate model output against leakage and PII rules

## Architecture at a glance

```text
prompt
  -> normalization and structural hardening
  -> Channel A: FSM + allowlist matching
  -> Channel B: rule engine
  -> 1oo2-inspired fail-closed voter
  -> PASS / BLOCK + audit record
  -> Channel C advisory analysis (post-verdict, non-authoritative)
  -> Channel D semantic similarity (optional, advisory-only)
```

For egress validation, the same philosophy is applied to model responses through a separate two-channel path focused on leakage, framing patterns, and PII-like output.

## Design principles

- Deterministic safety path: the verdict does not depend on an LLM.
- Fail closed: unknowns, disagreements, and internal faults block.
- Channel diversity: the main channels use different techniques to reduce common-mode failure.
- Advisory isolation: heuristic and semantic signals never override the safety decision.
- Auditable operation: every decision can be recorded and analyzed later.
- Init authorization: build-time token prevents race-to-init attacks; no default secrets in source code.

## Main components

### Channel A: FSM + allowlist

Channel A is a finite state machine with explicit tokenization, forbidden-pattern checks, and allowlist matching. It includes a watchdog and returns `Fault` on deadline violations, which the voter treats as `Block`.

### Channel B: Rule engine

Channel B performs structural and lexical analysis without regex or ML in its core rule path. Block rules are evaluated before allow rules.

### Channel C: advisory heuristics

This channel runs after the verdict and stores non-authoritative heuristics in the audit trail. It is useful for operator review, investigation, and tuning, but it does not gate the decision.

### Channel D: semantic similarity

This is an optional advisory feature:

- **8 learned attack centroids** derived from AdvBench + JailbreakBench via MiniLM + K-Means
- **384-dimensional embeddings** using `sentence-transformers/all-MiniLM-L6-v2`
- reference-dataset pipeline: feature extraction → clustering → hard-coding → CI tripwire
- centroid hash verification ensures semantic-boundary changes are detected and reviewed
- Advisory-only: never gates PASS/BLOCK outcomes, but provides semantic violation tags for operator review

*See `scripts/generate_centroids.py` for the centroid generation pipeline.*

### Egress firewall

The output side validates model responses against the original prompt and checks for leakage, framing signals, and PII-like content. It uses a two-channel fail-closed design separate from the ingress path.

## Why it feels different from typical guardrails

- It is closer to a policy firewall than a prompt classifier.
- It optimizes for narrow, explainable control boundaries rather than broad conversational flexibility.
- It is designed around reviewability, diagnostics, and regression testing.
- It treats semantic analysis as support tooling, not as the safety kernel.

## Who it is for

- teams building agents with tool use or multi-step workflows
- platform engineers adding a control layer in front of LLM APIs
- security-minded builders who prefer deterministic policy enforcement
- researchers exploring deterministic guardrail architectures

## Project layout

```text
policy-gate/
├── crates/
│   ├── firewall-core/     # Rust safety kernel
│   ├── firewall-cli/      # CLI for benchmarks and verification flows
│   ├── firewall-napi/     # Node native binding
│   ├── firewall-pyo3/     # Python binding
│   ├── firewall-wasm/     # WASM / edge target
│   └── firewall-fuzz/     # fuzz targets
├── scripts/               # smoke + conformance scripts
├── verification/          # Z3 models, corpora, analytics, benchmarks
├── deployment.md          # deployment notes
├── SAFETY_MANUAL.md       # deeper design and safety documentation
└── firewall.example.toml  # example configuration
```

## Supported runtimes

- Rust core library
- Node.js via `napi-rs`
- Python via `PyO3` and `maturin`
- WASM / edge builds

The safety function lives in Rust. The Node and Python packages are bindings around that core.

## Quickstart

### Node / TypeScript

```bash
npm install
npm run build:native
npm run build
npm run smoke
npm run conformance
```

Notes:

- `npm run build:native` builds the `firewall-napi` module and copies it to `native/index.node`.
- `npm run build` compiles [index.ts](./index.ts).
- `npm run smoke` exercises the basic wrapper paths.
- `npm run conformance` runs the shared corpus in [verification/conformance_corpus.json](./verification/conformance_corpus.json).

If the native `.node` file is not present yet, the wrapper falls back to a deterministic development stub.

### Python

```bash
python -m venv .venv
.venv\Scripts\activate
python -m pip install maturin
python -m maturin develop --manifest-path crates/firewall-pyo3/Cargo.toml
python scripts/smoke.py
python scripts/conformance.py
```

If you prefer wheel-based installation:

```powershell
python -m pip install maturin
python -m maturin build --manifest-path crates/firewall-pyo3/Cargo.toml
$wheel = (Get-ChildItem .\target\wheels\*.whl | Select-Object -First 1).FullName
python -m pip install $wheel
python scripts\smoke.py
python scripts\conformance.py
```

### Rust core

```bash
cargo test -p firewall-core
cargo clippy -p firewall-core -- -D warnings
```

### Semantic feature compile check

```bash
cargo check -p firewall-core --features semantic
```

### WASM / edge

The workspace includes `crates/firewall-wasm` for edge and browser-oriented builds where the semantic feature remains disabled.

## API surface

The Rust core exposes APIs for:

- single prompt evaluation
- raw input evaluation
- multi-message conversation evaluation
- output / egress evaluation
- profile-based initialization
- audit review tracking

The bindings expose matching subsets of that behavior for Node and Python.

## Configuration and profiles

The project supports:

- default and profile-based initialization
- custom intent patterns
- tenant-specific policy configuration
- TOML-based configuration via [firewall.example.toml](./firewall.example.toml)

The design is multi-tenant at the policy layer and single-tenant at the safety decision core.

## Verification and testing

Verification is a major part of the project rather than an afterthought.

### Automated checks in the repo

- Rust test suite for core behavior and regressions
- smoke and conformance checks for Node and Python bindings
- fuzz targets in `crates/firewall-fuzz`
- dataset regressions for harmful prompts
- false-positive rate measurement
- CI security auditing with `cargo-audit`

### Formal verification

The repository includes Z3 models for critical invariants:

- [verification/channel_a.smt2](./verification/channel_a.smt2)
- [verification/voter.smt2](./verification/voter.smt2)
- [verification/rule_engine.smt2](./verification/rule_engine.smt2)

Run them with:

```bash
python verification/run_proofs.py
```

There is also a pattern-change tripwire:

```bash
python verification/check_pattern_hash.py
```

### Regression datasets

```bash
cargo build --release -p firewall-cli
python verification/benchmark_datasets.py
python verification/fp_rate_test.py
```

### Review and analytics tooling

The repository also includes operator-facing support tooling:

- [verification/operator_review.py](./verification/operator_review.py)
- [verification/disagreement_analytics.py](./verification/disagreement_analytics.py)
- [verification/operator_review_architecture.md](./verification/operator_review_architecture.md)

## Hardening themes

The codebase contains explicit hardening work for areas such as:

- prompt injection markers and chat-template abuse
- obfuscation via Unicode confusables, combining marks, bidi controls, and separators
- low-and-slow probing detection through analytics
- watchdog behavior and fail-closed fault handling
- leakage and PII-like output validation
- audit integrity via chained HMAC-based records
- **session-aware multi-turn escalation detection** with sliding window memory

For the full design history and safety action log, see [SAFETY_MANUAL.md](./SAFETY_MANUAL.md).

## Limitations

`policy-gate` is intentionally narrow.

- It is not a general-purpose conversational safety solution.
- It works best when the allowed intent space is small and explicit.
- A deterministic allowlist-first design trades flexibility for predictability.
- Advisory semantic analysis is helpful, but it is not the trust anchor.
- The project is still under development and not appropriate for production or safety-critical deployment.

## When to use it

Use it when you want:

- a strict policy gate in front of model access
- deterministic PASS/BLOCK behavior
- auditable decisions and review workflows
- a defense-oriented wrapper around tool-using agents
- **multi-turn conversation protection** against escalation attacks

It is a weaker fit when you want:

- broad open-ended chatbot moderation
- nuanced intent classification over a large unconstrained prompt space
- a drop-in replacement for human review or policy design

## Related docs

- [SAFETY_MANUAL.md](./SAFETY_MANUAL.md)
- [deployment.md](./deployment.md)
- [RED_TEAM.md](./RED_TEAM.md)

## License

Apache License 2.0. See [LICENSE](./LICENSE).
