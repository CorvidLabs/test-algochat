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
