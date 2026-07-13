---
spec: algochat-harness.spec.md
---

## Context

This repository is the cross-language conformance harness for AlgoChat. Swift and TypeScript run the primary matrices; Python scripts exchange artifacts with all five implementation families; optional submodules provide external implementation runners.

## Related Modules

- No other canonical module is registered in this repository.

## Design Decisions

- Commit deterministic seeds, constants, and derivation vectors so independent implementations compare exact results.
- Keep standard and PSK protocols distinguishable by their protocol identifier and header size.
- Preserve sender-decryptable envelopes as part of bidirectional behavior.
- Treat localnet tests and generated cross-language artifacts as specialized verification beyond the deterministic governance lane.
