# test-algochat

Cross-implementation test suite for the AlgoChat protocol.

## Overview

This repository contains comprehensive tests to verify that all AlgoChat implementations are fully compatible with each other. The test suite validates encryption, decryption, and envelope encoding/decoding across all supported languages.

## Supported Implementations

| Language | Repository | Status |
|----------|------------|--------|
| Swift | [swift-algochat](https://github.com/CorvidLabs/swift-algochat) | ✓ |
| TypeScript | [ts-algochat](https://github.com/CorvidLabs/ts-algochat) | ✓ |
| Python | [py-algochat](https://github.com/CorvidLabs/py-algochat) | ✓ |
| Rust | [rs-algochat](https://github.com/CorvidLabs/rs-algochat) | ✓ |
| Kotlin | [kt-algochat](https://github.com/CorvidLabs/kt-algochat) | ✓ |

## Quick Start

```bash
# Run all offline crypto tests
./tests/run-all.sh crypto

# Run with localnet integration tests
algokit localnet start
./tests/run-all.sh all
algokit localnet stop
```

## Prerequisites

- **Swift 6.0+** - `swift --version`
- **Bun** - `bun --version`
- **Python 3.10+** - `python3 --version`
- **Rust** - `cargo --version` (optional)
- **Kotlin/JDK 17+** - `java --version` (optional)
- **AlgoKit** - `algokit --version` (for localnet tests)

## Test Coverage

### Message Types (20 total)

- **Basic strings**: empty, single char, whitespace, numbers, punctuation, newlines
- **Emoji**: simple emoji, ZWJ sequences (family emoji)
- **International scripts**: Chinese, Arabic, Japanese, Korean, Cyrillic, accented characters
- **Structured content**: JSON, HTML, URLs, code snippets
- **Size limits**: long text (~500 chars), max payload (882 bytes)

### Test Matrix

Each implementation is tested for:

1. **Key derivation** - HKDF-SHA256 produces identical keys from the same seed
2. **Encryption** - Messages encrypt to valid envelopes
3. **Decryption** - Messages decrypt correctly
4. **Bidirectional** - Senders can decrypt their own messages
5. **Cross-implementation** - Each implementation can decrypt envelopes from all others

### PSK v1.1 Protocol Tests

| Test | Description |
|------|-------------|
| Ratchet vectors | HKDF derivation matches reference (session/position/counter) |
| Envelope encode/decode | PSK envelope wire format round-trip (130-byte header) |
| Encrypt/decrypt | PSK message encryption and decryption |
| Bidirectional | Sender can decrypt own PSK messages |
| Cross-implementation | Each implementation decrypts PSK envelopes from all others |

#### PSK Ratchet Test Vectors

Initial PSK: 32 bytes of `0xAA`

| Counter | Session | Position | Expected PSK |
|---------|---------|----------|-------------|
| 0 | 0 | 0 | `2918fd48...` |
| 99 | 0 | 99 | `5b48a50a...` |
| 100 | 1 | 0 | `7a15d3ad...` |

## Running Tests

### Crypto Tests (Offline)

```bash
# Swift
swift run TestAlgoChat crypto

# TypeScript
bun test ts/crypto.test.ts

# Both (with cross-verification)
./tests/run-all.sh crypto
```

### Localnet Tests (Integration)

```bash
# Start localnet
algokit localnet start

# Run tests
./tests/run-all.sh localnet

# Stop localnet
algokit localnet stop
```

## Test Vectors

Test vectors are defined in `test-vectors.json` and include:

**Alice's seed:**
```
0000000000000000000000000000000000000000000000000000000000000001
```

**Bob's seed:**
```
0000000000000000000000000000000000000000000000000000000000000002
```

Keys are derived using HKDF-SHA256 with:
- Salt: `AlgoChat-v1-encryption`
- Info: `x25519-key`

Expected X25519 public keys:
- Alice: `a04407c78ff19a0bbd578588d6100bca4ed7f89acfc600666dbab1d36061c064`
- Bob: `b43231dc85ba0781ad3df9b8f8458a5e6f4c1030d0526ace9540300e0398ae03`

## Protocol Specification

AlgoChat uses:

- **X25519** for key agreement
- **ChaCha20-Poly1305** for authenticated encryption
- **HKDF-SHA256** for key derivation

### Envelope Format (126-byte header + ciphertext)

| Offset | Size | Field |
|--------|------|-------|
| 0 | 1 | Version (0x01) |
| 1 | 1 | Protocol ID (0x01) |
| 2-33 | 32 | Sender public key |
| 34-65 | 32 | Ephemeral public key |
| 66-77 | 12 | Nonce |
| 78-125 | 48 | Encrypted sender key |
| 126+ | var | Ciphertext + 16-byte tag |

### PSK v1.1 Protocol

AlgoChat PSK adds pre-shared key support with a two-level ratchet:

- **Session PSK** - Derived from initial PSK + session index (counter / 100)
- **Position PSK** - Derived from session PSK + position (counter % 100)
- **Hybrid encryption** - IKM = sharedSecret || currentPSK

#### PSK Envelope Format (130-byte header + ciphertext)

| Offset | Size | Field |
|--------|------|-------|
| 0 | 1 | Version (0x01) |
| 1 | 1 | Protocol ID (0x02) |
| 2-5 | 4 | Ratchet counter (big-endian uint32) |
| 6-37 | 32 | Sender public key |
| 38-69 | 32 | Ephemeral public key |
| 70-81 | 12 | Nonce |
| 82-129 | 48 | Encrypted sender key |
| 130+ | var | Ciphertext + 16-byte tag |

#### PSK HKDF Parameters

| Parameter | Value |
|-----------|-------|
| Session salt | `AlgoChat-PSK-Session` |
| Position salt | `AlgoChat-PSK-Position` |
| Hybrid info prefix | `AlgoChatV1-PSK` |
| Sender key info prefix | `AlgoChatV1-PSK-SenderKey` |
| Session size | 100 counters |
| Counter window | 200 |

#### PSK Ratchet Test Vectors (initial PSK = 32 bytes of 0xAA)

| Counter | Expected PSK |
|---------|-------------|
| Session 0 | `a031707ea9e9e50bd8ea4eb9a2bd368465ea1aff14caab293d38954b4717e888` |
| Session 1 | `994cffbb4f84fa5410d44574bb9fa7408a8c2f1ed2b3a00f5168fc74c71f7cea` |
| Counter 0 | `2918fd486b9bd024d712f6234b813c0f4167237d60c2c1fca37326b20497c165` |
| Counter 99 | `5b48a50a25261f6b63fe9c867b46be46de4d747c3477db6290045ba519a4d38b` |
| Counter 100 | `7a15d3add6a28858e6a1f1ea0d22bdb29b7e129a1330c4908d9b46a460992694` |

### Running PSK Tests

```bash
# Swift PSK tests
swift run TestAlgoChat psk

# TypeScript PSK tests
bun test ts/crypto.test.ts --grep "PSK"

# All tests (includes PSK)
./tests/run-all.sh crypto
```

## File Structure

```
test-algochat/
├── Package.swift              # Swift package
├── package.json               # TypeScript dependencies
├── test-vectors.json          # Shared test vectors
├── Sources/
│   └── TestAlgoChat/
│       ├── main.swift         # Swift CLI test runner
│       └── TestVectors.swift  # Shared test data
├── ts/
│   ├── test-vectors.ts        # TypeScript test vectors
│   ├── crypto.test.ts         # Crypto compatibility tests
│   └── localnet.test.ts       # Integration tests
├── tests/
│   └── run-all.sh             # Master test runner
└── .github/
    └── workflows/
        └── ci.yml             # GitHub Actions CI
```

## Generated Artifacts

During test runs, these directories are created:

| Directory | Description |
|-----------|-------------|
| `test-envelopes-swift/` | Swift-encrypted envelopes (20 messages) |
| `test-envelopes-ts/` | TypeScript-encrypted envelopes (20 messages) |
| `test-envelopes-python/` | Python-encrypted envelopes (20 messages) |
| `test-envelopes-swift-psk/` | Swift PSK-encrypted envelopes (20 messages) |
| `test-envelopes-ts-psk/` | TypeScript PSK-encrypted envelopes (20 messages) |
| `test-envelopes-py-psk/` | Python PSK-encrypted envelopes (20 messages) |
| `test-envelopes-rs-psk/` | Rust PSK-encrypted envelopes (20 messages) |
| `test-envelopes-kt-psk/` | Kotlin PSK-encrypted envelopes (20 messages) |

## CI/CD

GitHub Actions runs:

1. Swift tests on macOS
2. TypeScript tests on Ubuntu
3. Python tests on Ubuntu (3.10, 3.11, 3.12)
4. Rust tests on Ubuntu
5. Kotlin tests on Ubuntu
6. Cross-implementation verification

## Troubleshooting

### Swift build fails

```bash
swift package clean
swift package resolve
swift build
```

### TypeScript import errors

```bash
cd node_modules/ts-algochat
bun install && bun run build
cd -
bun install
```

### Localnet connection fails

```bash
algokit localnet status
algokit localnet stop
algokit localnet start
```

## License

MIT
