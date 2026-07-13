## MODIFIED

### REQUIREMENT REQ-algochat-harness-001

The harness SHALL provide identical deterministic identities, message corpora, protocol constants, byte conversions, and PSK ratchet vectors to its Swift and TypeScript verification surfaces.

Acceptance Criteria

- Alice and Bob keys derive from the committed seeds and HKDF labels.
- Hex conversions round-trip valid bytes and reject malformed input.

### REQUIREMENT REQ-algochat-harness-002

The harness SHALL verify version 1 key derivation, envelope recognition and encoding, authenticated encryption, sender and recipient decryption, message boundaries, and cross-implementation compatibility.

Acceptance Criteria

- Swift and TypeScript cover the committed message corpus and deterministic keys.
- Present artifacts are compared with exact expected plaintext.

### REQUIREMENT REQ-algochat-harness-003

The reference PSK implementation SHALL derive two-level counter keys and encode and decode the committed 130-byte-header wire format using a big-endian counter.

Acceptance Criteria

- Counters 0, 99, and 100 match committed derivation vectors.
- Decoding rejects invalid versions, identifiers, and undersized data.

### REQUIREMENT REQ-algochat-harness-004

PSK encryption and decryption SHALL bind X25519 key agreement and the current PSK through HKDF, authenticate payloads with ChaCha20-Poly1305, and support both recipient and sender decryption paths.

Acceptance Criteria

- Encryption rejects UTF-8 payloads larger than 878 bytes.
- Sender recovery uses the encrypted sender key; recipient recovery uses the direct hybrid key.

### REQUIREMENT REQ-algochat-harness-005

The counter validator SHALL reject replay, too-far-ahead counters, and sufficiently old too-far-behind counters while accepting unseen values within its configured window.

Acceptance Criteria

- Rejections report replay, too_far_ahead, or too_far_behind.
- Reset clears the highest counter, accepted count, and replay bitmap.

### REQUIREMENT REQ-algochat-harness-006

The Python helpers SHALL export and verify standard and PSK artifacts for the committed message corpus across Swift, TypeScript, Python, Rust, and Kotlin directories.

Acceptance Criteria

- PSK export writes deterministic message ordering and metadata.
- Verification skips absent directories but exits nonzero after any mismatch or invalid present envelope.

### REQUIREMENT REQ-algochat-harness-007

The harness SHALL exercise Algorand localnet send, receive, indexer, and protocol-detection behavior separately from its offline cryptographic matrix.

Acceptance Criteria

- Localnet configuration uses the committed algod and indexer endpoints.
- Offline verification remains runnable without localnet.

### REQUIREMENT REQ-algochat-harness-008

The harness SHALL produce a human-readable cross-implementation report from committed and generated results without changing protocol artifacts.

Acceptance Criteria

- Report generation consumes the repository's test and artifact evidence.
- Report output distinguishes implementation and protocol coverage.

### SPEC SECTION Purpose

Verify that the Swift, TypeScript, Python, Rust, and Kotlin AlgoChat implementations agree on deterministic keys, protocol constants, envelope formats, authenticated encryption, PSK ratchets, replay protection, localnet behavior, and cross-language artifacts.

### SPEC SECTION Public API

| Export | Description |
|--------|-------------|
| `TestVectors` | Swift namespace for deterministic keys, messages, protocol constants, PSK vectors, and localnet configuration. |
| `aliceSeedHex` | Swift hex seed for Alice's deterministic X25519 identity. |
| `bobSeedHex` | Swift hex seed for Bob's deterministic X25519 identity. |
| `aliceKeys` | Derives Alice's deterministic Swift key pair. |
| `bobKeys` | Derives Bob's deterministic Swift key pair. |
| `simpleMessage` | Swift-origin test message. |
| `tsMessage` | TypeScript-origin test message used by Swift verification. |
| `unicodeMessage` | Swift Unicode interoperability test message. |
| `longMessage` | Swift repeated long-text interoperability message. |
| `testMessages` | Swift named payload corpus spanning text, Unicode, structured data, and boundaries. |
| `protocolVersion` | Swift version 1 envelope byte. |
| `protocolID` | Swift standard-protocol identifier byte. |
| `headerSize` | Swift standard-envelope header length. |
| `tagSize` | Swift authenticated-encryption tag length. |
| `encryptedSenderKeySize` | Swift encrypted sender-key field length. |
| `maxPayloadSize` | Swift maximum standard-protocol plaintext length. |
| `pskProtocolID` | Swift PSK protocol identifier byte. |
| `pskHeaderSize` | Swift PSK envelope header length. |
| `pskMaxPayloadSize` | Swift maximum PSK plaintext length. |
| `pskSessionSize` | Swift counters per PSK ratchet session. |
| `pskCounterWindow` | Swift accepted PSK counter distance. |
| `pskSessionSalt` | Swift HKDF salt for PSK session derivation. |
| `pskPositionSalt` | Swift HKDF salt for PSK position derivation. |
| `pskHybridInfoPrefix` | Swift HKDF info prefix for hybrid message keys. |
| `pskSenderKeyInfoPrefix` | Swift HKDF info prefix for sender-key encryption. |
| `pskTestInitialPSKHex` | Swift initial PSK derivation vector. |
| `pskTestSession0Hex` | Swift expected session-zero PSK vector. |
| `pskTestSession1Hex` | Swift expected session-one PSK vector. |
| `pskTestCounter0Hex` | Swift expected counter-zero PSK vector. |
| `pskTestCounter99Hex` | Swift expected counter-99 PSK vector. |
| `pskTestCounter100Hex` | Swift expected counter-100 PSK vector. |
| `algodURL` | Swift localnet algod endpoint. |
| `algodToken` | Swift localnet algod development token. |
| `indexerURL` | Swift localnet indexer endpoint. |
| `hexString` | Swift Data and byte-array lowercase hexadecimal view. |
| `ALICE_SEED` | Python bytes seed for Alice's deterministic identity. |
| `BOB_SEED` | Python bytes seed for Bob's deterministic identity. |
| `TEST_PSK` | Python shared initial PSK for artifact exchange. |
| `ALICE_SEED_HEX` | TypeScript hex seed for Alice's deterministic X25519 identity. |
| `BOB_SEED_HEX` | TypeScript hex seed for Bob's deterministic X25519 identity. |
| `deriveKeysFromSeed` | Derives a deterministic X25519 key pair with the committed HKDF parameters. |
| `getAliceKeys` | Returns Alice's deterministic TypeScript key pair. |
| `getBobKeys` | Returns Bob's deterministic TypeScript key pair. |
| `SIMPLE_MESSAGE` | TypeScript-origin test message. |
| `SWIFT_MESSAGE` | Swift-origin test message. |
| `UNICODE_MESSAGE` | Unicode interoperability test message. |
| `LONG_MESSAGE` | Repeated long-text interoperability message. |
| `TEST_MESSAGES` | Named corpus covering empty, textual, Unicode, structured, and size-boundary payloads. |
| `PROTOCOL` | Version 1 envelope constants and size limits. |
| `PSK_PROTOCOL` | PSK v1.1 identifier, header, payload, session, and counter-window constants. |
| `PSK_HKDF` | PSK session, position, hybrid, and sender-key HKDF labels. |
| `PSK_RATCHET_VECTORS` | Committed PSK session and counter derivation results. |
| `LOCALNET` | Local Algorand node and indexer connection constants. |
| `KEY_DERIVATION` | Standard key-derivation salt and info labels. |
| `hexToBytes` | Converts validated even-length hexadecimal text to bytes. |
| `bytesToHex` | Converts bytes to lowercase hexadecimal text. |
| `bytesEqual` | Compares two byte arrays for equal length and contents. |
| `CounterResult` | Accepted or reasoned-rejection result for PSK counter validation. |
| `PskCounterValidator` | Tracks per-peer counter state and enforces replay and sliding-window rules. |
| `PskEnvelope` | Typed representation of the PSK v1.1 wire-envelope fields. |
| `derivePskForCounter` | Derives a position PSK from the initial key and two-level counter ratchet. |
| `encodePskEnvelope` | Serializes a PSK envelope in committed big-endian wire order. |
| `decodePskEnvelope` | Validates and decodes PSK wire bytes. |
| `isPskMessage` | Recognizes the committed PSK header and minimum length. |
| `pskEncryptMessage` | Encrypts a bounded message into a sender-decryptable PSK envelope. |
| `pskDecryptMessage` | Decrypts a PSK envelope through the sender or recipient path. |
| `export_envelopes` | Writes Python-generated version 1 envelopes for the message corpus. |
| `verify_envelopes` | Decrypts available version 1 artifacts from all implementations and fails on mismatch. |
| `export_psk_envelopes` | Writes ordered Python PSK envelopes and protocol metadata. |
| `verify_psk_envelopes` | Decrypts available PSK artifacts using their counters and metadata and fails on mismatch. |

### SPEC SECTION Invariants

1. Alice and Bob use the same committed 32-byte seeds in every language harness.
2. Version 1 envelopes use protocol identifier 1 and a 126-byte header; PSK v1.1 envelopes use identifier 2 and a 130-byte header.
3. PSK ratcheting derives session and position keys with committed HKDF salts, a session size of 100, and a counter window of 200.
4. Envelope decoding validates version, protocol identifier, and minimum encoded length before slicing fields.
5. Cross-implementation verification compares decrypted plaintext with the committed message corpus and exits unsuccessfully on any mismatch.
6. Counter validation rejects replay and out-of-window values while accepting unseen counters within the committed window.

### SPEC SECTION Behavioral Examples

- The all-zero-plus-one Alice seed derives the same X25519 public key in Swift and TypeScript.
- Counter 100 selects PSK session one, position zero, and the committed counter-100 vector.
- A recipient decrypts ciphertext using its static private key and the envelope ephemeral public key.
- A sender decrypts its own PSK envelope through the encrypted sender-key path.
- Python verification skips absent implementation directories but fails when any present artifact is invalid or decrypts incorrectly.

### SPEC SECTION Error Cases

| Error | When | Behavior |
|-------|------|----------|
| Invalid seed or hex | Input is malformed or has the wrong length | Reject conversion or key derivation. |
| Unsupported envelope | Version, protocol identifier, or encoded size is invalid | Throw before decryption. |
| Oversized payload | UTF-8 content exceeds the protocol maximum | Reject encryption. |
| Authentication failure | Keys, PSK, nonce, or ciphertext do not match | Propagate authenticated-decryption failure. |
| Replay or window violation | A PSK counter repeats or falls outside the allowed range | Return a specific rejection reason. |
| Artifact mismatch | A present cross-language envelope does not decrypt to its expected text | Count failure and exit nonzero. |
