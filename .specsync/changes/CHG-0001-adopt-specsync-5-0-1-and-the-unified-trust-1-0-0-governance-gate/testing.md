---
change: CHG-0001-adopt-specsync-5-0-1-and-the-unified-trust-1-0-0-governance-gate
artifact: testing
---

# Testing

- `fledge lanes run verify` validates committed vectors, the implementation registry, and patch integrity.
- `specsync check --strict --require-coverage 100 --force` validates every governed source and export.
- `specsync agents status` and `fledge plugins run trust doctor` validate integration and policy setup.
- Evidence covers `REQ-algochat-harness-001`, `REQ-algochat-harness-002`, `REQ-algochat-harness-003`, `REQ-algochat-harness-004`, `REQ-algochat-harness-005`, `REQ-algochat-harness-006`, `REQ-algochat-harness-007`, and `REQ-algochat-harness-008`.
