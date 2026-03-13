/**
 * PSK (Pre-Shared Key) v1.1 envelope encryption/decryption
 *
 * Implements the AlgoChat PSK protocol directly in the test harness
 * for cross-implementation verification, independent of any specific
 * library implementation.
 *
 * PSK envelope format (130-byte header + ciphertext):
 *   [0]     version (0x01)
 *   [1]     protocolId (0x02)
 *   [2-5]   ratchetCounter (big-endian uint32)
 *   [6-37]  senderPublicKey (32 bytes)
 *   [38-69] ephemeralPublicKey (32 bytes)
 *   [70-81] nonce (12 bytes)
 *   [82-129] encryptedSenderKey (48 bytes = 32 key + 16 tag)
 *   [130+]  ciphertext (variable, message + 16-byte tag)
 */

import { chacha20poly1305 } from '@noble/ciphers/chacha';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { randomBytes } from '@noble/ciphers/webcrypto';
import { x25519 } from '@noble/curves/ed25519';
import { PSK_PROTOCOL, PSK_HKDF, bytesToHex, hexToBytes } from './test-vectors';

// --- Types ---

export interface PskEnvelope {
    version: number;
    protocolId: number;
    ratchetCounter: number;
    senderPublicKey: Uint8Array;
    ephemeralPublicKey: Uint8Array;
    nonce: Uint8Array;
    encryptedSenderKey: Uint8Array;
    ciphertext: Uint8Array;
}

// --- Key agreement ---

function x25519ECDH(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
    return x25519.getSharedSecret(privateKey, publicKey);
}

function generateEphemeralKeyPair(): { privateKey: Uint8Array; publicKey: Uint8Array } {
    const privateKey = randomBytes(32);
    const publicKey = x25519.getPublicKey(privateKey);
    return { privateKey, publicKey };
}

// --- PSK Ratchet ---

/**
 * Derives the current PSK for a given counter value using two-level ratchet:
 *   session = HKDF(initialPSK, SESSION_SALT, counter / sessionSize)
 *   position = HKDF(session, POSITION_SALT, counter % sessionSize)
 */
export function derivePskForCounter(initialPSK: Uint8Array, counter: number): Uint8Array {
    const sessionIndex = Math.floor(counter / PSK_PROTOCOL.SESSION_SIZE);
    const positionIndex = counter % PSK_PROTOCOL.SESSION_SIZE;

    // Session-level derivation
    const sessionInfo = new Uint8Array(4);
    new DataView(sessionInfo.buffer).setUint32(0, sessionIndex, false); // big-endian
    const sessionKey = hkdf(
        sha256,
        initialPSK,
        new TextEncoder().encode(PSK_HKDF.SESSION_SALT),
        sessionInfo,
        32
    );

    // Position-level derivation
    const positionInfo = new Uint8Array(4);
    new DataView(positionInfo.buffer).setUint32(0, positionIndex, false);
    const positionKey = hkdf(
        sha256,
        sessionKey,
        new TextEncoder().encode(PSK_HKDF.POSITION_SALT),
        positionInfo,
        32
    );

    return positionKey;
}

// --- Helpers ---

function concatBytes(...arrays: Uint8Array[]): Uint8Array {
    const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
    const result = new Uint8Array(totalLength);
    let offset = 0;
    for (const arr of arrays) {
        result.set(arr, offset);
        offset += arr.length;
    }
    return result;
}

// --- Encode / Decode ---

export function encodePskEnvelope(envelope: PskEnvelope): Uint8Array {
    const totalSize =
        2 +  // version + protocolId
        4 +  // ratchetCounter
        32 + // senderPublicKey
        32 + // ephemeralPublicKey
        12 + // nonce
        48 + // encryptedSenderKey
        envelope.ciphertext.length;

    const result = new Uint8Array(totalSize);
    let offset = 0;

    result[offset++] = envelope.version;
    result[offset++] = envelope.protocolId;

    // Ratchet counter (4 bytes, big-endian)
    new DataView(result.buffer).setUint32(offset, envelope.ratchetCounter, false);
    offset += 4;

    result.set(envelope.senderPublicKey, offset);
    offset += 32;

    result.set(envelope.ephemeralPublicKey, offset);
    offset += 32;

    result.set(envelope.nonce, offset);
    offset += 12;

    result.set(envelope.encryptedSenderKey, offset);
    offset += 48;

    result.set(envelope.ciphertext, offset);

    return result;
}

export function decodePskEnvelope(data: Uint8Array): PskEnvelope {
    if (data.length < 2) {
        throw new Error(`PSK data too short: ${data.length} bytes`);
    }

    const version = data[0];
    const protocolId = data[1];

    if (version !== 0x01) {
        throw new Error(`Unsupported PSK version: ${version}`);
    }
    if (protocolId !== PSK_PROTOCOL.PROTOCOL_ID) {
        throw new Error(`Not a PSK envelope: protocolId=${protocolId}, expected ${PSK_PROTOCOL.PROTOCOL_ID}`);
    }

    const minSize = PSK_PROTOCOL.HEADER_SIZE + PSK_PROTOCOL.TAG_SIZE;
    if (data.length < minSize) {
        throw new Error(`PSK data too short: ${data.length} bytes, need at least ${minSize}`);
    }

    const ratchetCounter = new DataView(data.buffer, data.byteOffset).getUint32(2, false);

    return {
        version,
        protocolId,
        ratchetCounter,
        senderPublicKey: data.slice(6, 38),
        ephemeralPublicKey: data.slice(38, 70),
        nonce: data.slice(70, 82),
        encryptedSenderKey: data.slice(82, 130),
        ciphertext: data.slice(130),
    };
}

/**
 * Checks if data is a PSK (v1.1) AlgoChat message
 */
export function isPskMessage(data: Uint8Array): boolean {
    return data.length >= PSK_PROTOCOL.HEADER_SIZE + PSK_PROTOCOL.TAG_SIZE
        && data[0] === 0x01
        && data[1] === PSK_PROTOCOL.PROTOCOL_ID;
}

// --- Encrypt / Decrypt ---

/**
 * Encrypts a message using PSK v1.1 protocol.
 *
 * Hybrid key material: IKM = sharedSecret || currentPSK
 */
export function pskEncryptMessage(
    plaintext: string,
    senderPrivateKey: Uint8Array,
    senderPublicKey: Uint8Array,
    recipientPublicKey: Uint8Array,
    initialPSK: Uint8Array,
    counter: number,
): PskEnvelope {
    const messageBytes = new TextEncoder().encode(plaintext);

    if (messageBytes.length > PSK_PROTOCOL.MAX_PAYLOAD_SIZE) {
        throw new Error(`Message too large: ${messageBytes.length} bytes, max ${PSK_PROTOCOL.MAX_PAYLOAD_SIZE}`);
    }

    // Step 1: Derive current PSK from ratchet
    const currentPSK = derivePskForCounter(initialPSK, counter);

    // Step 2: Generate ephemeral key pair
    const ephemeral = generateEphemeralKeyPair();

    // Step 3: ECDH shared secret
    const sharedSecret = x25519ECDH(ephemeral.privateKey, recipientPublicKey);

    // Step 4: Hybrid key material = sharedSecret || currentPSK
    const hybridIKM = concatBytes(sharedSecret, currentPSK);

    // Step 5: Derive symmetric key using PSK info prefix
    const info = concatBytes(
        new TextEncoder().encode(PSK_HKDF.HYBRID_INFO_PREFIX),
        senderPublicKey,
        recipientPublicKey,
    );
    const symmetricKey = hkdf(sha256, hybridIKM, ephemeral.publicKey, info, 32);

    // Step 6: Generate random nonce
    const nonce = randomBytes(12);

    // Step 7: Encrypt message
    const cipher = chacha20poly1305(symmetricKey, nonce);
    const ciphertextWithTag = cipher.encrypt(messageBytes);

    // Step 8: Encrypt symmetric key for sender (bidirectional)
    const senderSharedSecret = x25519ECDH(ephemeral.privateKey, senderPublicKey);
    const senderHybridIKM = concatBytes(senderSharedSecret, currentPSK);

    const senderInfo = concatBytes(
        new TextEncoder().encode(PSK_HKDF.SENDER_KEY_INFO_PREFIX),
        senderPublicKey,
    );
    const senderEncryptionKey = hkdf(sha256, senderHybridIKM, ephemeral.publicKey, senderInfo, 32);

    const senderCipher = chacha20poly1305(senderEncryptionKey, nonce);
    const encryptedSenderKey = senderCipher.encrypt(symmetricKey);

    return {
        version: 0x01,
        protocolId: PSK_PROTOCOL.PROTOCOL_ID,
        ratchetCounter: counter,
        senderPublicKey,
        ephemeralPublicKey: ephemeral.publicKey,
        nonce,
        encryptedSenderKey,
        ciphertext: ciphertextWithTag,
    };
}

/**
 * Decrypts a PSK v1.1 envelope.
 * Auto-detects sender vs recipient path.
 */
export function pskDecryptMessage(
    envelope: PskEnvelope,
    myPrivateKey: Uint8Array,
    myPublicKey: Uint8Array,
    initialPSK: Uint8Array,
): string {
    // Derive current PSK
    const currentPSK = derivePskForCounter(initialPSK, envelope.ratchetCounter);

    const weAreSender = uint8ArrayEquals(myPublicKey, envelope.senderPublicKey);

    if (weAreSender) {
        return pskDecryptAsSender(envelope, myPrivateKey, myPublicKey, currentPSK);
    } else {
        return pskDecryptAsRecipient(envelope, myPrivateKey, myPublicKey, currentPSK);
    }
}

function pskDecryptAsRecipient(
    envelope: PskEnvelope,
    recipientPrivateKey: Uint8Array,
    recipientPublicKey: Uint8Array,
    currentPSK: Uint8Array,
): string {
    // ECDH
    const sharedSecret = x25519ECDH(recipientPrivateKey, envelope.ephemeralPublicKey);

    // Hybrid IKM
    const hybridIKM = concatBytes(sharedSecret, currentPSK);

    // Derive symmetric key
    const info = concatBytes(
        new TextEncoder().encode(PSK_HKDF.HYBRID_INFO_PREFIX),
        envelope.senderPublicKey,
        recipientPublicKey,
    );
    const symmetricKey = hkdf(sha256, hybridIKM, envelope.ephemeralPublicKey, info, 32);

    // Decrypt
    const cipher = chacha20poly1305(symmetricKey, envelope.nonce);
    const plaintext = cipher.decrypt(envelope.ciphertext);

    return new TextDecoder().decode(plaintext);
}

function pskDecryptAsSender(
    envelope: PskEnvelope,
    senderPrivateKey: Uint8Array,
    senderPublicKey: Uint8Array,
    currentPSK: Uint8Array,
): string {
    // ECDH with ephemeral
    const sharedSecret = x25519ECDH(senderPrivateKey, envelope.ephemeralPublicKey);
    const hybridIKM = concatBytes(sharedSecret, currentPSK);

    // Derive sender decryption key
    const senderInfo = concatBytes(
        new TextEncoder().encode(PSK_HKDF.SENDER_KEY_INFO_PREFIX),
        senderPublicKey,
    );
    const senderDecryptionKey = hkdf(sha256, hybridIKM, envelope.ephemeralPublicKey, senderInfo, 32);

    // Decrypt symmetric key
    const senderCipher = chacha20poly1305(senderDecryptionKey, envelope.nonce);
    const symmetricKey = senderCipher.decrypt(envelope.encryptedSenderKey);

    // Decrypt message
    const cipher = chacha20poly1305(symmetricKey, envelope.nonce);
    const plaintext = cipher.decrypt(envelope.ciphertext);

    return new TextDecoder().decode(plaintext);
}

function uint8ArrayEquals(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
        if (a[i] !== b[i]) return false;
    }
    return true;
}
