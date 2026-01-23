import AlgoChat
import Algorand
import AlgoKit
@preconcurrency import Crypto
import Foundation

// MARK: - Main Entry Point

@main
struct TestAlgoChatCLI {
    static func main() async throws {
        let args = CommandLine.arguments.dropFirst()
        let command = args.first ?? "all"

        switch command {
        case "crypto":
            try await runCryptoTests()
        case "localnet":
            try await runLocalnetTests()
        case "vectors":
            try printTestVectors()
        case "all":
            try await runAllTests()
        default:
            printUsage()
        }
    }

    static func printUsage() {
        print("""
        Usage: TestAlgoChat <command>

        Commands:
          crypto   - Run cryptographic compatibility tests (offline)
          localnet - Run integration tests (requires localnet)
          vectors  - Print computed test vectors
          all      - Run all tests

        """)
    }
}

// MARK: - Crypto Tests

private func runCryptoTests() async throws {
    print("=== Swift Crypto Tests ===\n")

    var passed = 0
    var failed = 0

    // Test 1: Key Derivation
    print("Test 1: Key Derivation from Seed")
    do {
        let (_, alicePublicKey) = try TestVectors.aliceKeys()
        let alicePublicKeyHex = alicePublicKey.rawRepresentation.hexString

        let (_, bobPublicKey) = try TestVectors.bobKeys()
        let bobPublicKeyHex = bobPublicKey.rawRepresentation.hexString

        print("  Alice seed: \(TestVectors.aliceSeedHex)")
        print("  Alice X25519 public key: \(alicePublicKeyHex)")
        print("  Bob seed: \(TestVectors.bobSeedHex)")
        print("  Bob X25519 public key: \(bobPublicKeyHex)")

        // Output for TypeScript comparison
        print("  \u{2713} Key derivation completed")
        passed += 1
    } catch {
        print("  \u{2717} FAILED: \(error)")
        failed += 1
    }

    // Test 2: Envelope Encoding/Decoding
    print("\nTest 2: Envelope Encoding/Decoding")
    do {
        let (alicePrivateKey, _) = try TestVectors.aliceKeys()
        let (_, bobPublicKey) = try TestVectors.bobKeys()

        // Encrypt a message
        let envelope = try MessageEncryptor.encrypt(
            message: TestVectors.simpleMessage,
            senderPrivateKey: alicePrivateKey,
            recipientPublicKey: bobPublicKey
        )

        // Encode to bytes
        let encoded = envelope.encode()
        print("  Encoded envelope: \(encoded.count) bytes")
        print("  Header: \(encoded.prefix(2).hexString)")
        print("  Sender pubkey: \(envelope.senderPublicKey.hexString)")
        print("  Ephemeral pubkey: \(envelope.ephemeralPublicKey.hexString)")
        print("  Nonce: \(envelope.nonce.hexString)")

        // Verify structure
        guard encoded[0] == TestVectors.protocolVersion else {
            throw TestError.assertion("Version mismatch: expected \(TestVectors.protocolVersion), got \(encoded[0])")
        }
        guard encoded[1] == TestVectors.protocolID else {
            throw TestError.assertion("Protocol ID mismatch")
        }
        guard encoded.count >= TestVectors.headerSize + TestVectors.tagSize else {
            throw TestError.assertion("Envelope too short")
        }

        // Decode back
        let decoded = try ChatEnvelope.decode(from: encoded)
        guard decoded.senderPublicKey == envelope.senderPublicKey else {
            throw TestError.assertion("Sender public key mismatch after decode")
        }
        guard decoded.ephemeralPublicKey == envelope.ephemeralPublicKey else {
            throw TestError.assertion("Ephemeral public key mismatch after decode")
        }
        guard decoded.nonce == envelope.nonce else {
            throw TestError.assertion("Nonce mismatch after decode")
        }
        guard decoded.ciphertext == envelope.ciphertext else {
            throw TestError.assertion("Ciphertext mismatch after decode")
        }

        print("  \u{2713} Envelope encoding/decoding passed")
        passed += 1
    } catch {
        print("  \u{2717} FAILED: \(error)")
        failed += 1
    }

    // Test 3: Encrypt/Decrypt Round Trip
    print("\nTest 3: Encrypt/Decrypt Round Trip")
    do {
        let (alicePrivateKey, _) = try TestVectors.aliceKeys()
        let (bobPrivateKey, bobPublicKey) = try TestVectors.bobKeys()

        // Alice encrypts for Bob
        let envelope = try MessageEncryptor.encrypt(
            message: TestVectors.simpleMessage,
            senderPrivateKey: alicePrivateKey,
            recipientPublicKey: bobPublicKey
        )

        // Bob decrypts
        let decrypted = try MessageEncryptor.decrypt(
            envelope: envelope,
            recipientPrivateKey: bobPrivateKey
        )

        guard let content = decrypted else {
            throw TestError.assertion("Decryption returned nil")
        }

        guard content.text == TestVectors.simpleMessage else {
            throw TestError.assertion("Message mismatch: expected '\(TestVectors.simpleMessage)', got '\(content.text)'")
        }

        print("  Original: \(TestVectors.simpleMessage)")
        print("  Decrypted: \(content.text)")
        print("  \u{2713} Round trip passed")
        passed += 1
    } catch {
        print("  \u{2717} FAILED: \(error)")
        failed += 1
    }

    // Test 4: Sender Decryption (Bidirectional)
    print("\nTest 4: Sender Decryption (Bidirectional)")
    do {
        let (alicePrivateKey, _) = try TestVectors.aliceKeys()
        let (_, bobPublicKey) = try TestVectors.bobKeys()

        // Alice encrypts for Bob
        let envelope = try MessageEncryptor.encrypt(
            message: TestVectors.simpleMessage,
            senderPrivateKey: alicePrivateKey,
            recipientPublicKey: bobPublicKey
        )

        // Alice decrypts her own message
        let decrypted = try MessageEncryptor.decrypt(
            envelope: envelope,
            recipientPrivateKey: alicePrivateKey
        )

        guard let content = decrypted else {
            throw TestError.assertion("Sender decryption returned nil")
        }

        guard content.text == TestVectors.simpleMessage else {
            throw TestError.assertion("Message mismatch")
        }

        print("  \u{2713} Sender can decrypt own messages")
        passed += 1
    } catch {
        print("  \u{2717} FAILED: \(error)")
        failed += 1
    }

    // Test 5: Export envelope for TypeScript
    print("\nTest 5: Export Test Envelope for TypeScript")
    do {
        let (alicePrivateKey, _) = try TestVectors.aliceKeys()
        let (_, bobPublicKey) = try TestVectors.bobKeys()

        // Create deterministic test envelope
        let envelope = try MessageEncryptor.encrypt(
            message: TestVectors.simpleMessage,
            senderPrivateKey: alicePrivateKey,
            recipientPublicKey: bobPublicKey
        )

        let encoded = envelope.encode()

        // Save to file for TypeScript to read
        let outputPath = "test-envelope-swift.hex"
        try encoded.hexString.write(toFile: outputPath, atomically: true, encoding: String.Encoding.utf8)
        print("  Saved envelope to \(outputPath) (\(encoded.count) bytes)")

        // Also save individual components for debugging
        let components = """
        version: \(encoded[0])
        protocol: \(encoded[1])
        senderPubKey: \(envelope.senderPublicKey.hexString)
        ephemeralPubKey: \(envelope.ephemeralPublicKey.hexString)
        nonce: \(envelope.nonce.hexString)
        encryptedSenderKey: \(envelope.encryptedSenderKey.hexString)
        ciphertext: \(envelope.ciphertext.hexString)
        full: \(encoded.hexString)
        message: \(TestVectors.simpleMessage)
        """
        try components.write(toFile: "test-envelope-swift.txt", atomically: true, encoding: String.Encoding.utf8)
        print("  Saved components to test-envelope-swift.txt")
        print("  \u{2713} Export completed")
        passed += 1
    } catch {
        print("  \u{2717} FAILED: \(error)")
        failed += 1
    }

    // Summary
    print("\n=== Summary ===")
    print("Passed: \(passed)")
    print("Failed: \(failed)")

    if failed > 0 {
        exit(1)
    }
}

// MARK: - Test Vector Printing

private func printTestVectors() throws {
    print("=== AlgoChat Test Vectors ===\n")

    let (alicePrivateKey, alicePublicKey) = try TestVectors.aliceKeys()
    let (bobPrivateKey, bobPublicKey) = try TestVectors.bobKeys()

    print("Alice:")
    print("  Seed (hex): \(TestVectors.aliceSeedHex)")
    print("  X25519 Private Key: \(alicePrivateKey.rawRepresentation.hexString)")
    print("  X25519 Public Key: \(alicePublicKey.rawRepresentation.hexString)")

    print("\nBob:")
    print("  Seed (hex): \(TestVectors.bobSeedHex)")
    print("  X25519 Private Key: \(bobPrivateKey.rawRepresentation.hexString)")
    print("  X25519 Public Key: \(bobPublicKey.rawRepresentation.hexString)")

    print("\nProtocol Constants:")
    print("  Version: 0x\(String(format: "%02x", TestVectors.protocolVersion))")
    print("  Protocol ID: 0x\(String(format: "%02x", TestVectors.protocolID))")
    print("  Header Size: \(TestVectors.headerSize)")
    print("  Tag Size: \(TestVectors.tagSize)")
    print("  Max Payload: \(TestVectors.maxPayloadSize)")

    print("\nKey Derivation Parameters:")
    print("  Salt: \"AlgoChat-v1-encryption\"")
    print("  Info: \"x25519-key\"")
    print("  Algorithm: HKDF-SHA256")
    print("  Output: 32 bytes")
}

// MARK: - Localnet Tests

private func runLocalnetTests() async throws {
    print("=== Swift Localnet Integration Tests ===\n")
    print("Note: Localnet tests require valid Algorand mnemonics.")
    print("The crypto tests use raw seeds for cross-implementation testing.\n")

    // Test: Read TypeScript envelope (if exists)
    print("Test: Read TypeScript Envelope")
    let tsEnvelopePath = "test-envelope-ts.hex"
    if FileManager.default.fileExists(atPath: tsEnvelopePath) {
        do {
            let hexContent = try String(contentsOfFile: tsEnvelopePath, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines)
            print("  TypeScript envelope: \(hexContent.count / 2) bytes")

            guard let noteData = Data(hexString: hexContent) else {
                throw TestError.assertion("Failed to decode hex envelope")
            }

            // Decode envelope
            let envelope = try ChatEnvelope.decode(from: noteData)
            print("  Envelope decoded, sender pubkey: \(envelope.senderPublicKey.hexString)")

            // Verify Alice's public key matches
            let (_, alicePublicKey) = try TestVectors.aliceKeys()
            guard envelope.senderPublicKey == alicePublicKey.rawRepresentation else {
                throw TestError.assertion("Sender public key mismatch - expected Alice's key")
            }

            // Decrypt as Bob
            let (bobPrivateKey, _) = try TestVectors.bobKeys()

            guard let content = try MessageEncryptor.decrypt(envelope: envelope, recipientPrivateKey: bobPrivateKey) else {
                throw TestError.assertion("Decryption returned nil (key-publish payload?)")
            }

            print("  Decrypted message: \(content.text)")

            // Verify it matches expected TypeScript message
            guard content.text == TestVectors.tsMessage else {
                throw TestError.assertion("Message mismatch: expected '\(TestVectors.tsMessage)', got '\(content.text)'")
            }

            print("  \u{2713} Successfully decrypted TypeScript envelope")
        } catch {
            print("  \u{2717} FAILED: \(error)")
            exit(1)
        }
    } else {
        print("  Skipping - test-envelope-ts.hex not found")
        print("  Run TypeScript crypto tests first to create an envelope")
    }

    print("\n=== Localnet tests complete ===")
}

// MARK: - Run All Tests

private func runAllTests() async throws {
    try printTestVectors()
    print("\n")
    try await runCryptoTests()
    print("\n")
    try await runLocalnetTests()
}

// MARK: - Errors

private enum TestError: Error, LocalizedError {
    case assertion(String)
    case testsFailed(Int)
    case localnetNotRunning

    var errorDescription: String? {
        switch self {
        case .assertion(let message):
            return "Assertion failed: \(message)"
        case .testsFailed(let count):
            return "\(count) test(s) failed"
        case .localnetNotRunning:
            return "Localnet is not running"
        }
    }
}
