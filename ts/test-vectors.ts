/**
 * Shared test vectors for cross-implementation testing
 */
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { x25519 } from '@noble/curves/ed25519';

// Alice's 32-byte seed (hex-encoded)
export const ALICE_SEED_HEX = '0000000000000000000000000000000000000000000000000000000000000001';

// Bob's 32-byte seed (hex-encoded)
export const BOB_SEED_HEX = '0000000000000000000000000000000000000000000000000000000000000002';

// Key derivation parameters (same as AlgoChat)
const KEY_DERIVATION_SALT = new TextEncoder().encode('AlgoChat-v1-encryption');
const KEY_DERIVATION_INFO = new TextEncoder().encode('x25519-key');

/**
 * Derives X25519 keys from a hex-encoded seed
 */
export function deriveKeysFromSeed(seedHex: string): { privateKey: Uint8Array; publicKey: Uint8Array } {
    const seed = hexToBytes(seedHex);
    if (seed.length !== 32) {
        throw new Error(`Seed must be 32 bytes, got ${seed.length}`);
    }

    // Derive encryption seed using HKDF-SHA256
    const encryptionSeed = hkdf(sha256, seed, KEY_DERIVATION_SALT, KEY_DERIVATION_INFO, 32);

    // Create X25519 key pair
    const privateKey = encryptionSeed;
    const publicKey = x25519.getPublicKey(privateKey);

    return { privateKey, publicKey };
}

/**
 * Get Alice's X25519 key pair
 */
export function getAliceKeys() {
    return deriveKeysFromSeed(ALICE_SEED_HEX);
}

/**
 * Get Bob's X25519 key pair
 */
export function getBobKeys() {
    return deriveKeysFromSeed(BOB_SEED_HEX);
}

// Test messages - different for each implementation to verify true bidirectional compatibility
export const SIMPLE_MESSAGE = 'Greetings from TypeScript! Verifying bidirectional compatibility.';
export const SWIFT_MESSAGE = 'Hello from Swift! Testing cross-implementation encryption.';
export const UNICODE_MESSAGE = 'Hello! \u{1F44B} Encrypted messaging on Algorand \u{1F512}';
export const LONG_MESSAGE = 'The quick brown fox jumps over the lazy dog. '.repeat(15);

// Comprehensive test messages (20 total) - must match Swift TestVectors.testMessages exactly
export const TEST_MESSAGES: Record<string, string> = {
    // Basic strings
    empty: '',
    single_char: 'X',
    whitespace: '   \t\n   ',
    numbers: '1234567890',
    punctuation: '!@#$%^&*()_+-=[]{}\\|;\':",./<>?',
    newlines: 'Line 1\nLine 2\nLine 3',

    // Emoji
    emoji_simple: 'Hello 👋 World 🌍',
    emoji_zwj: 'Family: 👨‍👩‍👧‍👦',

    // International scripts
    chinese: '你好世界 - Hello World',
    arabic: 'مرحبا بالعالم',
    japanese: 'こんにちは世界 カタカナ 漢字',
    korean: '안녕하세요 세계',
    accents: 'Café résumé naïve',
    cyrillic: 'Привет мир',

    // Structured content
    json: '{"key": "value", "num": 42}',
    html: '<div class="test">Content</div>',
    url: 'https://example.com/path?q=test&lang=en',
    code: 'func hello() { print("Hi") }',

    // Size limits
    long_text: 'The quick brown fox jumps over the lazy dog. '.repeat(11),
    max_payload: 'A'.repeat(882),
};

// Protocol constants
export const PROTOCOL = {
    VERSION: 0x01,
    PROTOCOL_ID: 0x01,
    HEADER_SIZE: 126,
    TAG_SIZE: 16,
    ENCRYPTED_SENDER_KEY_SIZE: 48,
    MAX_PAYLOAD_SIZE: 882,
};

// Localnet configuration
export const LOCALNET = {
    ALGOD_URL: 'http://localhost:4001',
    ALGOD_TOKEN: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    INDEXER_URL: 'http://localhost:8980',
};

// Key derivation parameters
export const KEY_DERIVATION = {
    SALT: 'AlgoChat-v1-encryption',
    INFO: 'x25519-key',
};

/**
 * Convert hex string to Uint8Array
 */
export function hexToBytes(hex: string): Uint8Array {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return bytes;
}

/**
 * Convert Uint8Array to hex string
 */
export function bytesToHex(bytes: Uint8Array): string {
    return Array.from(bytes)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');
}

/**
 * Compare two Uint8Arrays for equality
 */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
        if (a[i] !== b[i]) return false;
    }
    return true;
}
