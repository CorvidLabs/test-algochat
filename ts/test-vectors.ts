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

// Test messages
export const SIMPLE_MESSAGE = 'Hello from AlgoChat!';
export const UNICODE_MESSAGE = 'Hello! \u{1F44B} Encrypted messaging on Algorand \u{1F512}';
export const LONG_MESSAGE = 'The quick brown fox jumps over the lazy dog. '.repeat(15);

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
