# policy-gate Revision History

This file contains the extended revision log that was previously embedded at the
top of `SAFETY_MANUAL.md`.

For the current architectural description, use `SAFETY_MANUAL.md`.
For historical action tracking and older implementation notes, use this file.

The original in-manual history covered revisions `0.1` through `2.20`, including:

- early ingress hardening and fail-closed guard work
- multilingual and Unicode-normalization hardening rounds
- egress firewall introduction
- multiline and session-aware evaluation features
- coverage, gap-analysis, and verification alignment updates
- module-structure refactors aligning `lib.rs` with `init.rs`, `conversation.rs`,
  `ingress.rs`, `verdict_build.rs`, and `egress.rs`

If you want the full detailed row-by-row log preserved here, it can be pasted
back from git history; for now, the intent is to keep the main safety manual
readable and move archival revision tracking out of the main entry point.
