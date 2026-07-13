---
spec: algochat-harness.spec.md
---

## Test Plan

- **REQ-algochat-harness-001:** Swift and TypeScript vector definitions and crypto tests cover identities, messages, constants, conversions, and committed derivations.
- **REQ-algochat-harness-002:** Swift CLI and TypeScript crypto tests cover version 1 key, envelope, encryption, decryption, boundary, and cross-artifact behavior.
- **REQ-algochat-harness-003:** PSK tests cover ratchet vectors, big-endian encoding, round trips, detection, and invalid headers.
- **REQ-algochat-harness-004:** PSK crypto tests cover sender/recipient paths, tampering, wrong keys, and payload limits.
- **REQ-algochat-harness-005:** Counter tests cover replay, forward/backward windows, out-of-order input, pruning, custom windows, and reset.
- **REQ-algochat-harness-006:** Python scripts export and verify standard and PSK artifacts and propagate failures.
- **REQ-algochat-harness-007:** TypeScript and Swift localnet surfaces cover committed node and indexer behavior.
- **REQ-algochat-harness-008:** The TypeScript report generator consumes cross-implementation evidence.

`fledge lanes run verify` validates the JSON vectors, committed submodule registry, and patch integrity. `specsync check --strict --require-coverage 100 --force` validates every mapped source file and export.
