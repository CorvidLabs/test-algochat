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

    // MARK: - Protocol Constants

    public static let protocolVersion: UInt8 = 0x01
    public static let protocolID: UInt8 = 0x01
    public static let headerSize = 126
    public static let tagSize = 16
    public static let encryptedSenderKeySize = 48
    public static let maxPayloadSize = 882

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
