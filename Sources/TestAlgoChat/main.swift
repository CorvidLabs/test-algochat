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
        case "cross-impl":
            try await runCrossImplTests()
        case "localnet":
            try await runLocalnetTests()
        case "vectors":
            try printTestVectors()
        case "psk":
            try await runPSKCryptoTests()
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
          crypto     - Run cryptographic compatibility tests (offline)
          cross-impl - Verify decryption of envelopes from all implementations
          localnet   - Run integration tests (requires localnet)
          vectors    - Print computed test vectors
          psk        - Run PSK v1.1 protocol tests (offline)
          all        - Run all tests

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

    // Test 6: Multi-Message Round Trip
    print("\nTest 6: Multi-Message Round Trip (\(TestVectors.testMessages.count) messages)")
    do {
        let (alicePrivateKey, _) = try TestVectors.aliceKeys()
        let (bobPrivateKey, bobPublicKey) = try TestVectors.bobKeys()

        var multiPassed = 0
        var multiFailed = 0
        let sortedKeys = TestVectors.testMessages.keys.sorted()

        for key in sortedKeys {
            let message = TestVectors.testMessages[key]!

            do {
                // Alice encrypts for Bob
                let envelope = try MessageEncryptor.encrypt(
                    message: message,
                    senderPrivateKey: alicePrivateKey,
                    recipientPublicKey: bobPublicKey
                )

                // Bob decrypts
                let decrypted = try MessageEncryptor.decrypt(
                    envelope: envelope,
                    recipientPrivateKey: bobPrivateKey
                )

                guard let content = decrypted else {
                    throw TestError.assertion("Decryption returned nil for '\(key)'")
                }

                guard content.text == message else {
                    throw TestError.assertion("Message mismatch for '\(key)': expected '\(message)', got '\(content.text)'")
                }

                let displayMessage = message.count > 30 ? "\(message.prefix(30))..." : message
                let displayEscaped = displayMessage.replacingOccurrences(of: "\n", with: "\\n")
                    .replacingOccurrences(of: "\t", with: "\\t")
                print("  \u{2713} \(key): \"\(displayEscaped)\"")
                multiPassed += 1
            } catch {
                print("  \u{2717} \(key): FAILED - \(error)")
                multiFailed += 1
            }
        }

        print("  Multi-message: \(multiPassed)/\(TestVectors.testMessages.count) passed")
        if multiFailed > 0 {
            throw TestError.testsFailed(multiFailed)
        }
        passed += 1
    } catch {
        print("  \u{2717} FAILED: \(error)")
        failed += 1
    }

    // Test 7: Export All Test Envelopes
    print("\nTest 7: Export All Test Envelopes for Cross-Implementation")
    do {
        let (alicePrivateKey, _) = try TestVectors.aliceKeys()
        let (_, bobPublicKey) = try TestVectors.bobKeys()

        // Create output directory
        let outputDir = "test-envelopes-swift"
        try FileManager.default.createDirectory(atPath: outputDir, withIntermediateDirectories: true)

        let sortedKeys = TestVectors.testMessages.keys.sorted()
        var exportCount = 0

        for key in sortedKeys {
            let message = TestVectors.testMessages[key]!

            let envelope = try MessageEncryptor.encrypt(
                message: message,
                senderPrivateKey: alicePrivateKey,
                recipientPublicKey: bobPublicKey
            )

            let encoded = envelope.encode()
            let outputPath = "\(outputDir)/\(key).hex"
            try encoded.hexString.write(toFile: outputPath, atomically: true, encoding: .utf8)
            exportCount += 1
        }

        print("  Exported \(exportCount) envelopes to \(outputDir)/")
        print("  \u{2713} Export completed")
        passed += 1
    } catch {
        print("  \u{2717} FAILED: \(error)")
        failed += 1
    }

    // Test 8: Decrypt TypeScript Envelopes
    print("\nTest 8: Decrypt TypeScript Envelopes")
    do {
        let envelopeDir = "test-envelopes-ts"
        let (bobPrivateKey, _) = try TestVectors.bobKeys()

        guard FileManager.default.fileExists(atPath: envelopeDir) else {
            print("  SKIP: Run TypeScript tests first to generate envelopes")
            passed += 1
            throw TestError.assertion("skipped")
        }

        var crossPassed = 0
        var crossFailed = 0
        let sortedKeys = TestVectors.testMessages.keys.sorted()

        for key in sortedKeys {
            let envelopePath = "\(envelopeDir)/\(key).hex"
            guard FileManager.default.fileExists(atPath: envelopePath) else {
                print("  SKIP: \(key) - envelope not found")
                continue
            }

            do {
                let hexContent = try String(contentsOfFile: envelopePath, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines)
                guard let noteData = Data(hexString: hexContent) else {
                    throw TestError.assertion("Failed to decode hex")
                }

                let envelope = try ChatEnvelope.decode(from: noteData)
                guard let content = try MessageEncryptor.decrypt(envelope: envelope, recipientPrivateKey: bobPrivateKey) else {
                    throw TestError.assertion("Decryption returned nil")
                }

                let expectedMessage = TestVectors.testMessages[key]!
                guard content.text == expectedMessage else {
                    throw TestError.assertion("Message mismatch")
                }

                let displayMessage = expectedMessage.count > 30 ? "\(expectedMessage.prefix(30))..." : expectedMessage
                let displayEscaped = displayMessage.replacingOccurrences(of: "\n", with: "\\n")
                    .replacingOccurrences(of: "\t", with: "\\t")
                print("  \u{2713} \(key): \"\(displayEscaped)\"")
                crossPassed += 1
            } catch {
                print("  \u{2717} \(key): FAILED - \(error)")
                crossFailed += 1
            }
        }

        print("  TypeScript cross-impl: \(crossPassed)/\(sortedKeys.count) passed")
        if crossFailed > 0 {
            throw TestError.testsFailed(crossFailed)
        }
        passed += 1
    } catch TestError.assertion("skipped") {
        // Skip is fine
    } catch {
        print("  \u{2717} FAILED: \(error)")
        failed += 1
    }

    // Test 9: Decrypt Python Envelopes
    print("\nTest 9: Decrypt Python Envelopes")
    do {
        let envelopeDir = "test-envelopes-python"
        let (bobPrivateKey, _) = try TestVectors.bobKeys()

        guard FileManager.default.fileExists(atPath: envelopeDir) else {
            print("  SKIP: Run Python tests first to generate envelopes")
            passed += 1
            throw TestError.assertion("skipped")
        }

        var crossPassed = 0
        var crossFailed = 0
        let sortedKeys = TestVectors.testMessages.keys.sorted()

        for key in sortedKeys {
            let envelopePath = "\(envelopeDir)/\(key).hex"
            guard FileManager.default.fileExists(atPath: envelopePath) else {
                print("  SKIP: \(key) - envelope not found")
                continue
            }

            do {
                let hexContent = try String(contentsOfFile: envelopePath, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines)
                guard let noteData = Data(hexString: hexContent) else {
                    throw TestError.assertion("Failed to decode hex")
                }

                let envelope = try ChatEnvelope.decode(from: noteData)
                guard let content = try MessageEncryptor.decrypt(envelope: envelope, recipientPrivateKey: bobPrivateKey) else {
                    throw TestError.assertion("Decryption returned nil")
                }

                let expectedMessage = TestVectors.testMessages[key]!
                guard content.text == expectedMessage else {
                    throw TestError.assertion("Message mismatch")
                }

                let displayMessage = expectedMessage.count > 30 ? "\(expectedMessage.prefix(30))..." : expectedMessage
                let displayEscaped = displayMessage.replacingOccurrences(of: "\n", with: "\\n")
                    .replacingOccurrences(of: "\t", with: "\\t")
                print("  \u{2713} \(key): \"\(displayEscaped)\"")
                crossPassed += 1
            } catch {
                print("  \u{2717} \(key): FAILED - \(error)")
                crossFailed += 1
            }
        }

        print("  Python cross-impl: \(crossPassed)/\(sortedKeys.count) passed")
        if crossFailed > 0 {
            throw TestError.testsFailed(crossFailed)
        }
        passed += 1
    } catch TestError.assertion("skipped") {
        // Skip is fine
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

// MARK: - PSK Crypto Tests

private func runPSKCryptoTests() async throws {
    print("=== Swift PSK v1.1 Tests ===\n")

    var passed = 0
    var failed = 0

    // Test 1: PSK Ratchet Vectors
    print("Test 1: PSK Ratchet Vectors")
    do {
        guard let initialPSK = Data(hexString: TestVectors.pskTestInitialPSKHex) else {
            throw TestError.assertion("Failed to decode initial PSK hex")
        }

        // Session 0
        let session0 = PSKRatchet.deriveSessionPSK(initialPSK: initialPSK, sessionIndex: 0)
        guard session0.hexString == TestVectors.pskTestSession0Hex else {
            throw TestError.assertion("Session 0 mismatch: \(session0.hexString)")
        }
        print("  \u{2713} Session 0: \(session0.hexString)")

        // Session 1
        let session1 = PSKRatchet.deriveSessionPSK(initialPSK: initialPSK, sessionIndex: 1)
        guard session1.hexString == TestVectors.pskTestSession1Hex else {
            throw TestError.assertion("Session 1 mismatch: \(session1.hexString)")
        }
        print("  \u{2713} Session 1: \(session1.hexString)")

        // Counter 0 (session 0, position 0)
        let counter0 = PSKRatchet.derivePSKAtCounter(initialPSK: initialPSK, counter: 0)
        guard counter0.hexString == TestVectors.pskTestCounter0Hex else {
            throw TestError.assertion("Counter 0 mismatch: \(counter0.hexString)")
        }
        print("  \u{2713} Counter 0: \(counter0.hexString)")

        // Counter 99 (session 0, position 99)
        let counter99 = PSKRatchet.derivePSKAtCounter(initialPSK: initialPSK, counter: 99)
        guard counter99.hexString == TestVectors.pskTestCounter99Hex else {
            throw TestError.assertion("Counter 99 mismatch: \(counter99.hexString)")
        }
        print("  \u{2713} Counter 99: \(counter99.hexString)")

        // Counter 100 (session 1, position 0)
        let counter100 = PSKRatchet.derivePSKAtCounter(initialPSK: initialPSK, counter: 100)
        guard counter100.hexString == TestVectors.pskTestCounter100Hex else {
            throw TestError.assertion("Counter 100 mismatch: \(counter100.hexString)")
        }
        print("  \u{2713} Counter 100: \(counter100.hexString)")

        passed += 1
    } catch {
        print("  \u{2717} FAILED: \(error)")
        failed += 1
    }

    // Test 2: PSK Envelope Encoding/Decoding
    print("\nTest 2: PSK Envelope Encoding/Decoding")
    do {
        let (alicePrivateKey, _) = try TestVectors.aliceKeys()
        let (_, bobPublicKey) = try TestVectors.bobKeys()

        guard let testPSK = Data(hexString: TestVectors.pskTestInitialPSKHex) else {
            throw TestError.assertion("Failed to decode test PSK")
        }

        let currentPSK = PSKRatchet.derivePSKAtCounter(initialPSK: testPSK, counter: 0)

        let envelope = try MessageEncryptor.encryptPSK(
            message: TestVectors.simpleMessage,
            senderPrivateKey: alicePrivateKey,
            recipientPublicKey: bobPublicKey,
            currentPSK: currentPSK,
            ratchetCounter: 0
        )

        let encoded = envelope.encode()
        print("  Encoded PSK envelope: \(encoded.count) bytes")
        print("  Header: \(encoded.prefix(2).hexString)")
        guard encoded[0] == 0x01 else {
            throw TestError.assertion("Version mismatch")
        }
        guard encoded[1] == TestVectors.pskProtocolID else {
            throw TestError.assertion("Protocol ID mismatch: expected \(TestVectors.pskProtocolID), got \(encoded[1])")
        }
        guard encoded.count >= TestVectors.pskHeaderSize + TestVectors.tagSize else {
            throw TestError.assertion("Envelope too short")
        }

        let decoded = try PSKEnvelope.decode(from: encoded)
        guard decoded.ratchetCounter == envelope.ratchetCounter else {
            throw TestError.assertion("Counter mismatch")
        }
        guard decoded.senderPublicKey == envelope.senderPublicKey else {
            throw TestError.assertion("Sender public key mismatch")
        }
        guard decoded.ephemeralPublicKey == envelope.ephemeralPublicKey else {
            throw TestError.assertion("Ephemeral public key mismatch")
        }
        guard decoded.nonce == envelope.nonce else {
            throw TestError.assertion("Nonce mismatch")
        }
        guard decoded.ciphertext == envelope.ciphertext else {
            throw TestError.assertion("Ciphertext mismatch")
        }

        print("  \u{2713} PSK envelope encoding/decoding passed")
        passed += 1
    } catch {
        print("  \u{2717} FAILED: \(error)")
        failed += 1
    }

    // Test 3: PSK Encrypt/Decrypt Round Trip
    print("\nTest 3: PSK Encrypt/Decrypt Round Trip")
    do {
        let (alicePrivateKey, _) = try TestVectors.aliceKeys()
        let (bobPrivateKey, bobPublicKey) = try TestVectors.bobKeys()

        guard let testPSK = Data(hexString: TestVectors.pskTestInitialPSKHex) else {
            throw TestError.assertion("Failed to decode test PSK")
        }

        let currentPSK = PSKRatchet.derivePSKAtCounter(initialPSK: testPSK, counter: 0)

        let envelope = try MessageEncryptor.encryptPSK(
            message: TestVectors.simpleMessage,
            senderPrivateKey: alicePrivateKey,
            recipientPublicKey: bobPublicKey,
            currentPSK: currentPSK,
            ratchetCounter: 0
        )

        let decrypted = try MessageEncryptor.decryptPSK(
            envelope: envelope,
            recipientPrivateKey: bobPrivateKey,
            currentPSK: currentPSK
        )

        guard let content = decrypted else {
            throw TestError.assertion("Decryption returned nil")
        }
        guard content.text == TestVectors.simpleMessage else {
            throw TestError.assertion("Message mismatch")
        }

        print("  \u{2713} PSK round trip passed")
        passed += 1
    } catch {
        print("  \u{2717} FAILED: \(error)")
        failed += 1
    }

    // Test 4: PSK Sender Decryption (Bidirectional)
    print("\nTest 4: PSK Sender Decryption (Bidirectional)")
    do {
        let (alicePrivateKey, _) = try TestVectors.aliceKeys()
        let (_, bobPublicKey) = try TestVectors.bobKeys()

        guard let testPSK = Data(hexString: TestVectors.pskTestInitialPSKHex) else {
            throw TestError.assertion("Failed to decode test PSK")
        }

        let currentPSK = PSKRatchet.derivePSKAtCounter(initialPSK: testPSK, counter: 0)

        let envelope = try MessageEncryptor.encryptPSK(
            message: TestVectors.simpleMessage,
            senderPrivateKey: alicePrivateKey,
            recipientPublicKey: bobPublicKey,
            currentPSK: currentPSK,
            ratchetCounter: 0
        )

        let decrypted = try MessageEncryptor.decryptPSK(
            envelope: envelope,
            recipientPrivateKey: alicePrivateKey,
            currentPSK: currentPSK
        )

        guard let content = decrypted else {
            throw TestError.assertion("Sender decryption returned nil")
        }
        guard content.text == TestVectors.simpleMessage else {
            throw TestError.assertion("Message mismatch")
        }

        print("  \u{2713} PSK sender can decrypt own messages")
        passed += 1
    } catch {
        print("  \u{2717} FAILED: \(error)")
        failed += 1
    }

    // Test 5: Export PSK Test Envelopes
    print("\nTest 5: Export PSK Test Envelopes for Cross-Implementation")
    do {
        let (alicePrivateKey, _) = try TestVectors.aliceKeys()
        let (_, bobPublicKey) = try TestVectors.bobKeys()

        guard let testPSK = Data(hexString: TestVectors.pskTestInitialPSKHex) else {
            throw TestError.assertion("Failed to decode test PSK")
        }

        let outputDir = "test-envelopes-swift-psk"
        try FileManager.default.createDirectory(atPath: outputDir, withIntermediateDirectories: true)

        let sortedKeys = TestVectors.testMessages.keys.sorted()
        var exportCount = 0

        for (index, key) in sortedKeys.enumerated() {
            let message = TestVectors.testMessages[key]!
            let counter = UInt32(index)
            let currentPSK = PSKRatchet.derivePSKAtCounter(initialPSK: testPSK, counter: counter)

            let envelope = try MessageEncryptor.encryptPSK(
                message: message,
                senderPrivateKey: alicePrivateKey,
                recipientPublicKey: bobPublicKey,
                currentPSK: currentPSK,
                ratchetCounter: counter
            )

            let encoded = envelope.encode()
            let outputPath = "\(outputDir)/\(key).hex"
            try encoded.hexString.write(toFile: outputPath, atomically: true, encoding: .utf8)
            exportCount += 1
        }

        print("  Exported \(exportCount) PSK envelopes to \(outputDir)/")
        print("  \u{2713} PSK export completed")
        passed += 1
    } catch {
        print("  \u{2717} FAILED: \(error)")
        failed += 1
    }

    // Test 6: Multi-Message PSK Round Trip
    print("\nTest 6: Multi-Message PSK Round Trip (\(TestVectors.testMessages.count) messages)")
    do {
        let (alicePrivateKey, _) = try TestVectors.aliceKeys()
        let (bobPrivateKey, bobPublicKey) = try TestVectors.bobKeys()

        guard let testPSK = Data(hexString: TestVectors.pskTestInitialPSKHex) else {
            throw TestError.assertion("Failed to decode test PSK")
        }

        var multiPassed = 0
        var multiFailed = 0
        let sortedKeys = TestVectors.testMessages.keys.sorted()

        for (index, key) in sortedKeys.enumerated() {
            let message = TestVectors.testMessages[key]!
            let counter = UInt32(index)
            let currentPSK = PSKRatchet.derivePSKAtCounter(initialPSK: testPSK, counter: counter)

            do {
                let envelope = try MessageEncryptor.encryptPSK(
                    message: message,
                    senderPrivateKey: alicePrivateKey,
                    recipientPublicKey: bobPublicKey,
                    currentPSK: currentPSK,
                    ratchetCounter: counter
                )

                let decrypted = try MessageEncryptor.decryptPSK(
                    envelope: envelope,
                    recipientPrivateKey: bobPrivateKey,
                    currentPSK: currentPSK
                )

                guard let content = decrypted else {
                    throw TestError.assertion("Decryption returned nil for '\(key)'")
                }

                guard content.text == message else {
                    throw TestError.assertion("Message mismatch for '\(key)'")
                }

                let displayMessage = message.count > 30 ? "\(message.prefix(30))..." : message
                let displayEscaped = displayMessage.replacingOccurrences(of: "\n", with: "\\n")
                    .replacingOccurrences(of: "\t", with: "\\t")
                print("  \u{2713} \(key): \"\(displayEscaped)\"")
                multiPassed += 1
            } catch {
                print("  \u{2717} \(key): FAILED - \(error)")
                multiFailed += 1
            }
        }

        print("  PSK multi-message: \(multiPassed)/\(TestVectors.testMessages.count) passed")
        if multiFailed > 0 {
            throw TestError.testsFailed(multiFailed)
        }
        passed += 1
    } catch {
        print("  \u{2717} FAILED: \(error)")
        failed += 1
    }

    // Summary
    print("\n=== PSK Test Summary ===")
    print("Passed: \(passed)")
    print("Failed: \(failed)")

    if failed > 0 {
        exit(1)
    }
}

// MARK: - Cross-Implementation Tests

private func runCrossImplTests() async throws {
    print("=== Cross-Implementation Verification ===\n")
    print("Swift decrypting envelopes from all implementations\n")

    let (bobPrivateKey, _) = try TestVectors.bobKeys()
    let implementations = ["swift", "ts", "python", "rust", "kotlin"]

    var totalPassed = 0
    var totalFailed = 0

    for impl in implementations {
        let envelopeDir = "test-envelopes-\(impl)"

        guard FileManager.default.fileExists(atPath: envelopeDir) else {
            print("\(impl): SKIP - directory not found")
            continue
        }

        var passed = 0
        var failed = 0
        let sortedKeys = TestVectors.testMessages.keys.sorted()

        for key in sortedKeys {
            let envelopePath = "\(envelopeDir)/\(key).hex"
            guard FileManager.default.fileExists(atPath: envelopePath) else {
                continue
            }

            do {
                let hexContent = try String(contentsOfFile: envelopePath, encoding: .utf8)
                    .trimmingCharacters(in: .whitespacesAndNewlines)
                guard let noteData = Data(hexString: hexContent) else {
                    throw TestError.assertion("Failed to decode hex")
                }

                let envelope = try ChatEnvelope.decode(from: noteData)
                guard let content = try MessageEncryptor.decrypt(
                    envelope: envelope,
                    recipientPrivateKey: bobPrivateKey
                ) else {
                    throw TestError.assertion("Decryption returned nil")
                }

                let expectedMessage = TestVectors.testMessages[key]!
                guard content.text == expectedMessage else {
                    throw TestError.assertion("Message mismatch")
                }

                passed += 1
            } catch {
                failed += 1
            }
        }

        print("\(impl): \(passed)/\(passed + failed) passed")
        totalPassed += passed
        totalFailed += failed
    }

    print("\n=== Summary ===")
    print("Total: \(totalPassed)/\(totalPassed + totalFailed) passed")

    if totalFailed > 0 {
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
    try await runPSKCryptoTests()
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
