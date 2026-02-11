@preconcurrency import Crypto
import Foundation

/// Shared test vectors for cross-implementation testing
public enum TestVectors {
    // MARK: - Test Seeds (32-byte hex-encoded seeds for X25519 key derivation)

    /// Alice's 32-byte seed (deterministic test value)
    /// Using all-zeros seed for simplicity (this is NOT secure for production)
    public static let aliceSeedHex = "0000000000000000000000000000000000000000000000000000000000000001"

    /// Bob's 32-byte seed (deterministic test value)
    public static let bobSeedHex = "0000000000000000000000000000000000000000000000000000000000000002"

    // MARK: - Key Derivation from Seeds

    /// Derives X25519 keys from a seed using AlgoChat's HKDF parameters
    public static func deriveKeysFromSeed(_ seedHex: String) throws -> (
        privateKey: Curve25519.KeyAgreement.PrivateKey,
        publicKey: Curve25519.KeyAgreement.PublicKey
    ) {
        guard let seed = Data(hexString: seedHex), seed.count == 32 else {
            throw TestError.invalidSeed
        }

        // Use HKDF with AlgoChat parameters
        let salt = Data("AlgoChat-v1-encryption".utf8)
        let info = Data("x25519-key".utf8)

        let derivedKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: seed),
            salt: salt,
            info: info,
            outputByteCount: 32
        )

        let keyData = derivedKey.withUnsafeBytes { Data($0) }
        let privateKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: keyData)
        return (privateKey, privateKey.publicKey)
    }

    /// Get Alice's X25519 key pair
    public static func aliceKeys() throws -> (
        privateKey: Curve25519.KeyAgreement.PrivateKey,
        publicKey: Curve25519.KeyAgreement.PublicKey
    ) {
        try deriveKeysFromSeed(aliceSeedHex)
    }

    /// Get Bob's X25519 key pair
    public static func bobKeys() throws -> (
        privateKey: Curve25519.KeyAgreement.PrivateKey,
        publicKey: Curve25519.KeyAgreement.PublicKey
    ) {
        try deriveKeysFromSeed(bobSeedHex)
    }

    enum TestError: Error {
        case invalidSeed
    }

    // MARK: - Test Messages

    /// Simple text message for testing (Swift → TypeScript direction)
    public static let simpleMessage = "Hello from Swift! Testing cross-implementation encryption."

    /// Message that TypeScript uses (TypeScript → Swift direction)
    public static let tsMessage = "Greetings from TypeScript! Verifying bidirectional compatibility."

    /// Message with special characters
    public static let unicodeMessage = "Hello! \u{1F44B} Encrypted messaging on Algorand \u{1F512}"

    /// Long message (near max payload)
    public static let longMessage = String(repeating: "The quick brown fox jumps over the lazy dog. ", count: 15)

    // MARK: - Comprehensive Test Messages (20 total)

    /// Dictionary of test messages for comprehensive cross-implementation testing
    public static let testMessages: [String: String] = [
        // Basic strings
        "empty": "",
        "single_char": "X",
        "whitespace": "   \t\n   ",
        "numbers": "1234567890",
        "punctuation": "!@#$%^&*()_+-=[]{}\\|;':\",./<>?",
        "newlines": "Line 1\nLine 2\nLine 3",

        // Emoji
        "emoji_simple": "Hello 👋 World 🌍",
        "emoji_zwj": "Family: 👨‍👩‍👧‍👦",

        // International scripts
        "chinese": "你好世界 - Hello World",
        "arabic": "مرحبا بالعالم",
        "japanese": "こんにちは世界 カタカナ 漢字",
        "korean": "안녕하세요 세계",
        "accents": "Café résumé naïve",
        "cyrillic": "Привет мир",

        // Structured content
        "json": "{\"key\": \"value\", \"num\": 42}",
        "html": "<div class=\"test\">Content</div>",
        "url": "https://example.com/path?q=test&lang=en",
        "code": "func hello() { print(\"Hi\") }",

        // Size limits
        "long_text": String(repeating: "The quick brown fox jumps over the lazy dog. ", count: 11),
        "max_payload": String(repeating: "A", count: 882),
    ]

    // MARK: - Protocol Constants

    public static let protocolVersion: UInt8 = 0x01
    public static let protocolID: UInt8 = 0x01
    public static let headerSize = 126
    public static let tagSize = 16
    public static let encryptedSenderKeySize = 48
    public static let maxPayloadSize = 882

    // MARK: - PSK Protocol Constants

    public static let pskProtocolID: UInt8 = 0x02
    public static let pskHeaderSize = 130
    public static let pskMaxPayloadSize = 878
    public static let pskSessionSize: UInt32 = 100
    public static let pskCounterWindow: UInt32 = 200

    // MARK: - PSK HKDF Constants

    public static let pskSessionSalt = "AlgoChat-PSK-Session"
    public static let pskPositionSalt = "AlgoChat-PSK-Position"
    public static let pskHybridInfoPrefix = "AlgoChatV1-PSK"
    public static let pskSenderKeyInfoPrefix = "AlgoChatV1-PSK-SenderKey"

    // MARK: - PSK Ratchet Test Vectors (initial PSK = 32 bytes of 0xAA)

    public static let pskTestInitialPSKHex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    public static let pskTestSession0Hex = "a031707ea9e9e50bd8ea4eb9a2bd368465ea1aff14caab293d38954b4717e888"
    public static let pskTestSession1Hex = "994cffbb4f84fa5410d44574bb9fa7408a8c2f1ed2b3a00f5168fc74c71f7cea"
    public static let pskTestCounter0Hex = "2918fd486b9bd024d712f6234b813c0f4167237d60c2c1fca37326b20497c165"
    public static let pskTestCounter99Hex = "5b48a50a25261f6b63fe9c867b46be46de4d747c3477db6290045ba519a4d38b"
    public static let pskTestCounter100Hex = "7a15d3add6a28858e6a1f1ea0d22bdb29b7e129a1330c4908d9b46a460992694"

    // MARK: - Localnet Configuration

    public static let algodURL = "http://localhost:4001"
    public static let algodToken = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    public static let indexerURL = "http://localhost:8980"
}

/// Hex encoding/decoding helpers
public extension Data {
    var hexString: String {
        map { String(format: "%02x", $0) }.joined()
    }

    init?(hexString: String) {
        let hex = hexString.lowercased()
        guard hex.count % 2 == 0 else { return nil }

        var data = Data()
        var index = hex.startIndex

        while index < hex.endIndex {
            let nextIndex = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<nextIndex], radix: 16) else {
                return nil
            }
            data.append(byte)
            index = nextIndex
        }
        self = data
    }
}

/// Array hex helpers
public extension Array where Element == UInt8 {
    var hexString: String {
        Data(self).hexString
    }

    init?(hexString: String) {
        guard let data = Data(hexString: hexString) else { return nil }
        self = [UInt8](data)
    }
}
