---
spec: algochat-harness.spec.md
---

## Requirements

### REQ-algochat-harness-001

The harness SHALL provide identical deterministic identities, message corpora, protocol constants, byte conversions, and PSK ratchet vectors to its Swift and TypeScript verification surfaces.

Acceptance Criteria

- Alice and Bob keys derive from the committed seeds and HKDF labels.
- Hex conversions round-trip valid bytes and reject malformed input.

### REQ-algochat-harness-002

The harness SHALL verify version 1 key derivation, envelope recognition and encoding, authenticated encryption, sender and recipient decryption, message boundaries, and cross-implementation compatibility.

Acceptance Criteria

- Swift and TypeScript cover the committed message corpus and deterministic keys.
- Present artifacts are compared with exact expected plaintext.

### REQ-algochat-harness-003

The reference PSK implementation SHALL derive two-level counter keys and encode and decode the committed 130-byte-header wire format using a big-endian counter.

Acceptance Criteria

- Counters 0, 99, and 100 match committed derivation vectors.
- Decoding rejects invalid versions, identifiers, and undersized data.

### REQ-algochat-harness-004

PSK encryption and decryption SHALL bind X25519 key agreement and the current PSK through HKDF, authenticate payloads with ChaCha20-Poly1305, and support both recipient and sender decryption paths.

Acceptance Criteria

- Encryption rejects UTF-8 payloads larger than 878 bytes.
- Sender recovery uses the encrypted sender key; recipient recovery uses the direct hybrid key.

### REQ-algochat-harness-005

The counter validator SHALL reject replay, too-far-ahead counters, and sufficiently old too-far-behind counters while accepting unseen values within its configured window.

Acceptance Criteria

- Rejections report replay, too_far_ahead, or too_far_behind.
- Reset clears the highest counter, accepted count, and replay bitmap.

### REQ-algochat-harness-006

The Python helpers SHALL export and verify standard and PSK artifacts for the committed message corpus across Swift, TypeScript, Python, Rust, and Kotlin directories.

Acceptance Criteria

- PSK export writes deterministic message ordering and metadata.
- Verification skips absent directories but exits nonzero after any mismatch or invalid present envelope.

### REQ-algochat-harness-007

The harness SHALL exercise Algorand localnet send, receive, indexer, and protocol-detection behavior separately from its offline cryptographic matrix.

Acceptance Criteria

- Localnet configuration uses the committed algod and indexer endpoints.
- Offline verification remains runnable without localnet.

### REQ-algochat-harness-008

The harness SHALL produce a human-readable cross-implementation report from committed and generated results without changing protocol artifacts.

Acceptance Criteria

- Report generation consumes the repository's test and artifact evidence.
- Report output distinguishes implementation and protocol coverage.

## Out of Scope

- Implementing production AlgoChat libraries, managing localnet lifecycle, changing protocol constants, or modifying harness product code in this governance migration.
