# AlgoChat Cross-Implementation Tests

Verifies that Swift and TypeScript AlgoChat implementations can interoperate.

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
- **Bun** - `bun --version` (install: `curl -fsSL https://bun.sh/install | bash`)
- **AlgoKit** - `algokit --version` (for localnet tests)

## Test Suites

### 1. Crypto Tests (Offline)

Verifies cryptographic compatibility without blockchain:

- **Key Derivation** - Same mnemonic produces identical X25519 keys
- **Envelope Encoding** - Wire format matches byte-for-byte
- **Encrypt/Decrypt** - Cross-implementation decryption works
- **Bidirectional** - Sender can decrypt own messages

```bash
# Swift only
swift run TestAlgoChat crypto

# TypeScript only
bun test ts/crypto.test.ts

# Both
./tests/run-all.sh crypto
```

### 2. Localnet Tests (Integration)

End-to-end tests on Algorand localnet:

- **Swift → TypeScript** - Swift sends, TS receives/decrypts
- **TypeScript → Swift** - TS sends, Swift receives/decrypts
- **Reply Threads** - Cross-implementation replies work

```bash
# Start localnet
algokit localnet start

# Run tests
./tests/run-all.sh localnet

# Stop localnet
algokit localnet stop
```

## Test Vectors

Print computed test vectors for debugging:

```bash
swift run TestAlgoChat vectors
```

Output includes:
- Alice and Bob's Algorand addresses
- Derived X25519 public keys
- Protocol constants
- Key derivation parameters

## File Structure

```
_tests/test-algochat/
├── Package.swift              # Swift package
├── package.json               # TypeScript dependencies
├── tsconfig.json              # TypeScript config
├── Sources/
│   └── TestAlgoChat/
│       ├── main.swift         # Swift CLI test runner
│       └── TestVectors.swift  # Shared test data
├── ts/
│   ├── test-vectors.ts        # Matching test vectors
│   ├── crypto.test.ts         # Crypto compatibility tests
│   └── localnet.test.ts       # Integration tests
├── tests/
│   └── run-all.sh             # Master test runner
└── README.md
```

## Generated Files

During test runs, these files are created for cross-implementation verification:

| File | Description |
|------|-------------|
| `test-envelope-swift.hex` | Hex-encoded envelope from Swift |
| `test-envelope-swift.txt` | Swift envelope components |
| `test-envelope-ts.hex` | Hex-encoded envelope from TypeScript |
| `test-envelope-ts.txt` | TypeScript envelope components |
| `swift-message-txid.txt` | Transaction ID of Swift's localnet message |
| `ts-message-txid.txt` | Transaction ID of TypeScript's localnet message |

## Test Seeds

Both implementations use the same deterministic 32-byte seeds:

**Alice:**
```
0000000000000000000000000000000000000000000000000000000000000001
```

**Bob:**
```
0000000000000000000000000000000000000000000000000000000000000002
```

Keys are derived using HKDF-SHA256 with:
- Salt: `AlgoChat-v1-encryption`
- Info: `x25519-key`

This produces identical X25519 key pairs in both Swift and TypeScript:
- Alice: `a04407c78ff19a0bbd578588d6100bca4ed7f89acfc600666dbab1d36061c064`
- Bob: `b43231dc85ba0781ad3df9b8f8458a5e6f4c1030d0526ace9540300e0398ae03`

## Troubleshooting

### Swift build fails

```bash
# Clean and rebuild
swift package clean
swift package resolve
swift build
```

### TypeScript import errors

```bash
# Rebuild ts-algochat
cd ../../../../typescript/ts-algochat
bun run build
cd -
bun install
```

### Localnet connection fails

```bash
# Check localnet status
algokit localnet status

# Restart localnet
algokit localnet stop
algokit localnet start
```

### Key derivation mismatch

Verify both implementations use:
- Salt: `AlgoChat-v1-encryption`
- Info: `x25519-key`
- Algorithm: HKDF-SHA256
- Output: 32 bytes

## Protocol Compatibility

Both implementations must produce identical:

1. **Key Derivation**: HKDF-SHA256(seed, salt, info) → X25519 private key
2. **Envelope Format**: `[version][protocol][senderPubKey][ephemeralPubKey][nonce][encryptedSenderKey][ciphertext]`
3. **Encryption**: Ephemeral ECDH → HKDF → ChaCha20-Poly1305
