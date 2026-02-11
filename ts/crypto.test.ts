/**
 * Crypto compatibility tests for AlgoChat
 *
 * Tests that TypeScript and Swift implementations produce compatible output.
 */

import { describe, test, expect, beforeAll } from 'bun:test';
import { encryptMessage, decryptMessage, encodeEnvelope, decodeEnvelope, isChatMessage } from 'ts-algochat';
import {
    ALICE_SEED_HEX,
    BOB_SEED_HEX,
    getAliceKeys,
    getBobKeys,
    deriveKeysFromSeed,
    SIMPLE_MESSAGE,
    SWIFT_MESSAGE,
    UNICODE_MESSAGE,
    TEST_MESSAGES,
    PROTOCOL,
    PSK_RATCHET_VECTORS,
    PSK_HKDF,
    bytesToHex,
    hexToBytes,
    bytesEqual,
} from './test-vectors';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { readFileSync, existsSync, writeFileSync } from 'fs';

// Derived keys (computed in beforeAll)
let aliceKeys: { privateKey: Uint8Array; publicKey: Uint8Array };
let bobKeys: { privateKey: Uint8Array; publicKey: Uint8Array };

beforeAll(() => {
    // Derive keys from seeds
    aliceKeys = getAliceKeys();
    bobKeys = getBobKeys();

    console.log('\n=== TypeScript Test Vectors ===');
    console.log('Alice:');
    console.log(`  Seed: ${ALICE_SEED_HEX}`);
    console.log(`  X25519 Public Key: ${bytesToHex(aliceKeys.publicKey)}`);
    console.log('Bob:');
    console.log(`  Seed: ${BOB_SEED_HEX}`);
    console.log(`  X25519 Public Key: ${bytesToHex(bobKeys.publicKey)}`);
    console.log('');
});

describe('Key Derivation', () => {
    test('derives consistent keys from seed', () => {
        // Re-derive to ensure consistency
        const keys = getAliceKeys();

        expect(bytesEqual(keys.publicKey, aliceKeys.publicKey)).toBe(true);
        expect(bytesEqual(keys.privateKey, aliceKeys.privateKey)).toBe(true);
    });

    test('produces 32-byte keys', () => {
        expect(aliceKeys.privateKey.length).toBe(32);
        expect(aliceKeys.publicKey.length).toBe(32);
        expect(bobKeys.privateKey.length).toBe(32);
        expect(bobKeys.publicKey.length).toBe(32);
    });

    test.skipIf(!existsSync('test-envelope-swift.txt'))('matches Swift key derivation (if available)', () => {
        const vectorsPath = 'test-envelope-swift.txt';
        const content = readFileSync(vectorsPath, 'utf-8');
        const senderPubKeyMatch = content.match(/senderPubKey: ([a-f0-9]+)/);

        if (senderPubKeyMatch) {
            const swiftAlicePubKey = senderPubKeyMatch[1];
            const tsAlicePubKey = bytesToHex(aliceKeys.publicKey);
            expect(tsAlicePubKey).toBe(swiftAlicePubKey);
            console.log('  Swift Alice pubkey matches TypeScript');
        }
    });
});

describe('Envelope Encoding', () => {
    test('encodes envelope with correct header', () => {
        const envelope = encryptMessage(
            SIMPLE_MESSAGE,
            aliceKeys.privateKey,
            aliceKeys.publicKey,
            bobKeys.publicKey
        );

        expect(envelope.version).toBe(PROTOCOL.VERSION);
        expect(envelope.protocolId).toBe(PROTOCOL.PROTOCOL_ID);
        expect(envelope.senderPublicKey.length).toBe(32);
        expect(envelope.ephemeralPublicKey.length).toBe(32);
        expect(envelope.nonce.length).toBe(12);
        expect(envelope.encryptedSenderKey.length).toBe(PROTOCOL.ENCRYPTED_SENDER_KEY_SIZE);
    });

    test('encode/decode roundtrip', () => {
        const envelope = encryptMessage(
            SIMPLE_MESSAGE,
            aliceKeys.privateKey,
            aliceKeys.publicKey,
            bobKeys.publicKey
        );

        const encoded = encodeEnvelope(envelope);
        expect(encoded.length).toBeGreaterThanOrEqual(PROTOCOL.HEADER_SIZE + PROTOCOL.TAG_SIZE);

        const decoded = decodeEnvelope(encoded);
        expect(bytesEqual(decoded.senderPublicKey, envelope.senderPublicKey)).toBe(true);
        expect(bytesEqual(decoded.ephemeralPublicKey, envelope.ephemeralPublicKey)).toBe(true);
        expect(bytesEqual(decoded.nonce, envelope.nonce)).toBe(true);
        expect(bytesEqual(decoded.encryptedSenderKey, envelope.encryptedSenderKey)).toBe(true);
        expect(bytesEqual(decoded.ciphertext, envelope.ciphertext)).toBe(true);
    });

    test('isChatMessage detects valid envelopes', () => {
        const envelope = encryptMessage(
            SIMPLE_MESSAGE,
            aliceKeys.privateKey,
            aliceKeys.publicKey,
            bobKeys.publicKey
        );
        const encoded = encodeEnvelope(envelope);

        expect(isChatMessage(encoded)).toBe(true);
        expect(isChatMessage(new Uint8Array([0x00, 0x01]))).toBe(false);
        expect(isChatMessage(new Uint8Array([0x01, 0x00]))).toBe(false);
    });

    test('export envelope for Swift comparison', () => {
        const envelope = encryptMessage(
            SIMPLE_MESSAGE,
            aliceKeys.privateKey,
            aliceKeys.publicKey,
            bobKeys.publicKey
        );
        const encoded = encodeEnvelope(envelope);

        // Save hex-encoded envelope
        writeFileSync('test-envelope-ts.hex', bytesToHex(encoded));

        // Save components for debugging
        const components = [
            `version: ${envelope.version}`,
            `protocol: ${envelope.protocolId}`,
            `senderPubKey: ${bytesToHex(envelope.senderPublicKey)}`,
            `ephemeralPubKey: ${bytesToHex(envelope.ephemeralPublicKey)}`,
            `nonce: ${bytesToHex(envelope.nonce)}`,
            `encryptedSenderKey: ${bytesToHex(envelope.encryptedSenderKey)}`,
            `ciphertext: ${bytesToHex(envelope.ciphertext)}`,
            `full: ${bytesToHex(encoded)}`,
            `message: ${SIMPLE_MESSAGE}`,
        ].join('\n');
        writeFileSync('test-envelope-ts.txt', components);

        console.log(`  Exported envelope: ${encoded.length} bytes`);
    });
});

describe('Encryption/Decryption', () => {
    test('encrypt/decrypt roundtrip', () => {
        const envelope = encryptMessage(
            SIMPLE_MESSAGE,
            aliceKeys.privateKey,
            aliceKeys.publicKey,
            bobKeys.publicKey
        );

        const decrypted = decryptMessage(envelope, bobKeys.privateKey, bobKeys.publicKey);

        expect(decrypted).not.toBeNull();
        expect(decrypted!.text).toBe(SIMPLE_MESSAGE);
    });

    test('sender can decrypt own message', () => {
        const envelope = encryptMessage(
            SIMPLE_MESSAGE,
            aliceKeys.privateKey,
            aliceKeys.publicKey,
            bobKeys.publicKey
        );

        const decrypted = decryptMessage(envelope, aliceKeys.privateKey, aliceKeys.publicKey);

        expect(decrypted).not.toBeNull();
        expect(decrypted!.text).toBe(SIMPLE_MESSAGE);
    });

    test('handles unicode messages', () => {
        const envelope = encryptMessage(
            UNICODE_MESSAGE,
            aliceKeys.privateKey,
            aliceKeys.publicKey,
            bobKeys.publicKey
        );

        const decrypted = decryptMessage(envelope, bobKeys.privateKey, bobKeys.publicKey);

        expect(decrypted).not.toBeNull();
        expect(decrypted!.text).toBe(UNICODE_MESSAGE);
    });

    test('wrong key fails to decrypt', () => {
        const envelope = encryptMessage(
            SIMPLE_MESSAGE,
            aliceKeys.privateKey,
            aliceKeys.publicKey,
            bobKeys.publicKey
        );

        // Try to decrypt with wrong keys
        expect(() => {
            // Create a random key pair from different seed
            const wrongKeys = deriveKeysFromSeed('0000000000000000000000000000000000000000000000000000000000000099');
            decryptMessage(envelope, wrongKeys.privateKey, wrongKeys.publicKey);
        }).toThrow();
    });
});

describe('Cross-Implementation', () => {
    test.skipIf(!existsSync('test-envelope-swift.hex'))('decrypt Swift envelope', () => {
        const swiftEnvelopePath = 'test-envelope-swift.hex';
        const hexContent = readFileSync(swiftEnvelopePath, 'utf-8').trim();
        const encoded = hexToBytes(hexContent);

        expect(isChatMessage(encoded)).toBe(true);

        const envelope = decodeEnvelope(encoded);
        console.log(`  Swift envelope: ${encoded.length} bytes`);
        console.log(`  Sender pubkey: ${bytesToHex(envelope.senderPublicKey)}`);

        // Verify the sender is Alice
        expect(bytesEqual(envelope.senderPublicKey, aliceKeys.publicKey)).toBe(true);

        // Decrypt as Bob
        const decrypted = decryptMessage(envelope, bobKeys.privateKey, bobKeys.publicKey);

        expect(decrypted).not.toBeNull();
        expect(decrypted!.text).toBe(SWIFT_MESSAGE);
        console.log(`  Decrypted: "${decrypted!.text}"`);
    });
});

describe('Multi-Message Tests', () => {
    const messageKeys = Object.keys(TEST_MESSAGES).sort();

    test('all message types encrypt/decrypt correctly', () => {
        let passed = 0;
        let failed = 0;

        for (const key of messageKeys) {
            const message = TEST_MESSAGES[key];

            try {
                const envelope = encryptMessage(
                    message,
                    aliceKeys.privateKey,
                    aliceKeys.publicKey,
                    bobKeys.publicKey
                );

                const decrypted = decryptMessage(envelope, bobKeys.privateKey, bobKeys.publicKey);

                expect(decrypted).not.toBeNull();
                expect(decrypted!.text).toBe(message);
                passed++;

                const displayMessage = message.length > 30 ? message.substring(0, 30) + '...' : message;
                const displayEscaped = displayMessage.replace(/\n/g, '\\n').replace(/\t/g, '\\t');
                console.log(`  ✓ ${key}: "${displayEscaped}"`);
            } catch (error) {
                failed++;
                console.log(`  ✗ ${key}: FAILED - ${error}`);
            }
        }

        console.log(`  Multi-message: ${passed}/${messageKeys.length} passed`);
        expect(failed).toBe(0);
    });

    test('sender can decrypt all message types', () => {
        for (const key of messageKeys) {
            const message = TEST_MESSAGES[key];

            const envelope = encryptMessage(
                message,
                aliceKeys.privateKey,
                aliceKeys.publicKey,
                bobKeys.publicKey
            );

            const decrypted = decryptMessage(envelope, aliceKeys.privateKey, aliceKeys.publicKey);

            expect(decrypted).not.toBeNull();
            expect(decrypted!.text).toBe(message);
        }
    });

    test('export all test envelopes for Swift', () => {
        const { mkdirSync, writeFileSync } = require('fs');
        const outputDir = 'test-envelopes-ts';

        try {
            mkdirSync(outputDir, { recursive: true });
        } catch {
            // Directory may already exist
        }

        let exportCount = 0;

        for (const key of messageKeys) {
            const message = TEST_MESSAGES[key];

            const envelope = encryptMessage(
                message,
                aliceKeys.privateKey,
                aliceKeys.publicKey,
                bobKeys.publicKey
            );

            const encoded = encodeEnvelope(envelope);
            writeFileSync(`${outputDir}/${key}.hex`, bytesToHex(encoded));
            exportCount++;
        }

        console.log(`  Exported ${exportCount} envelopes to ${outputDir}/`);
    });

    test.skipIf(!existsSync('test-envelopes-swift'))('decrypt all Swift envelopes', () => {
        const envelopeDir = 'test-envelopes-swift';
        let passed = 0;
        let failed = 0;
        let skipped = 0;

        for (const key of messageKeys) {
            const envelopePath = `${envelopeDir}/${key}.hex`;
            if (!existsSync(envelopePath)) {
                console.log(`  SKIP: ${key} - envelope not found`);
                skipped++;
                continue;
            }

            try {
                const hexContent = readFileSync(envelopePath, 'utf-8').trim();
                const encoded = hexToBytes(hexContent);
                const envelope = decodeEnvelope(encoded);

                const decrypted = decryptMessage(envelope, bobKeys.privateKey, bobKeys.publicKey);

                expect(decrypted).not.toBeNull();

                const expectedMessage = TEST_MESSAGES[key];
                expect(decrypted!.text).toBe(expectedMessage);
                passed++;

                const displayMessage =
                    expectedMessage.length > 30 ? expectedMessage.substring(0, 30) + '...' : expectedMessage;
                const displayEscaped = displayMessage.replace(/\n/g, '\\n').replace(/\t/g, '\\t');
                console.log(`  ✓ ${key}: "${displayEscaped}"`);
            } catch (error) {
                failed++;
                console.log(`  ✗ ${key}: FAILED - ${error}`);
            }
        }

        console.log(`  Cross-impl verification: ${passed} passed, ${failed} failed, ${skipped} skipped (of ${messageKeys.length})`);
        expect(failed).toBe(0);
    });

    test.skipIf(!existsSync('test-envelopes-python'))('decrypt all Python envelopes', () => {
        const envelopeDir = 'test-envelopes-python';
        let passed = 0;
        let failed = 0;
        let skipped = 0;

        for (const key of messageKeys) {
            const envelopePath = `${envelopeDir}/${key}.hex`;
            if (!existsSync(envelopePath)) {
                console.log(`  SKIP: ${key} - envelope not found`);
                skipped++;
                continue;
            }

            try {
                const hexContent = readFileSync(envelopePath, 'utf-8').trim();
                const encoded = hexToBytes(hexContent);
                const envelope = decodeEnvelope(encoded);

                const decrypted = decryptMessage(envelope, bobKeys.privateKey, bobKeys.publicKey);

                expect(decrypted).not.toBeNull();

                const expectedMessage = TEST_MESSAGES[key];
                expect(decrypted!.text).toBe(expectedMessage);
                passed++;

                const displayMessage =
                    expectedMessage.length > 30 ? expectedMessage.substring(0, 30) + '...' : expectedMessage;
                const displayEscaped = displayMessage.replace(/\n/g, '\\n').replace(/\t/g, '\\t');
                console.log(`  ✓ ${key}: "${displayEscaped}"`);
            } catch (error) {
                failed++;
                console.log(`  ✗ ${key}: FAILED - ${error}`);
            }
        }

        console.log(`  Python cross-impl verification: ${passed} passed, ${failed} failed, ${skipped} skipped (of ${messageKeys.length})`);
        expect(failed).toBe(0);
    });

    test.skipIf(!existsSync('test-envelopes-rust'))('decrypt all Rust envelopes', () => {
        const envelopeDir = 'test-envelopes-rust';
        let passed = 0;
        let failed = 0;
        let skipped = 0;

        for (const key of messageKeys) {
            const envelopePath = `${envelopeDir}/${key}.hex`;
            if (!existsSync(envelopePath)) {
                skipped++;
                continue;
            }

            try {
                const hexContent = readFileSync(envelopePath, 'utf-8').trim();
                const encoded = hexToBytes(hexContent);
                const envelope = decodeEnvelope(encoded);

                const decrypted = decryptMessage(envelope, bobKeys.privateKey, bobKeys.publicKey);

                expect(decrypted).not.toBeNull();

                const expectedMessage = TEST_MESSAGES[key];
                expect(decrypted!.text).toBe(expectedMessage);
                passed++;
            } catch (error) {
                failed++;
                console.log(`  ✗ ${key}: FAILED - ${error}`);
            }
        }

        console.log(`  Rust cross-impl verification: ${passed} passed, ${failed} failed, ${skipped} skipped (of ${messageKeys.length})`);
        expect(failed).toBe(0);
    });

    test.skipIf(!existsSync('test-envelopes-kotlin'))('decrypt all Kotlin envelopes', () => {
        const envelopeDir = 'test-envelopes-kotlin';
        let passed = 0;
        let failed = 0;
        let skipped = 0;

        for (const key of messageKeys) {
            const envelopePath = `${envelopeDir}/${key}.hex`;
            if (!existsSync(envelopePath)) {
                skipped++;
                continue;
            }

            try {
                const hexContent = readFileSync(envelopePath, 'utf-8').trim();
                const encoded = hexToBytes(hexContent);
                const envelope = decodeEnvelope(encoded);

                const decrypted = decryptMessage(envelope, bobKeys.privateKey, bobKeys.publicKey);

                expect(decrypted).not.toBeNull();

                const expectedMessage = TEST_MESSAGES[key];
                expect(decrypted!.text).toBe(expectedMessage);
                passed++;
            } catch (error) {
                failed++;
                console.log(`  ✗ ${key}: FAILED - ${error}`);
            }
        }

        console.log(`  Kotlin cross-impl verification: ${passed} passed, ${failed} failed, ${skipped} skipped (of ${messageKeys.length})`);
        expect(failed).toBe(0);
    });
});

describe('PSK Ratchet Vectors', () => {
    test('derives correct session and position PSKs', () => {
        const initialPSK = hexToBytes(PSK_RATCHET_VECTORS.initialPSK);

        // Session 0
        const session0Info = new Uint8Array(4); // 0 as 4-byte big-endian
        const session0 = hkdf(
            sha256,
            initialPSK,
            new TextEncoder().encode(PSK_HKDF.SESSION_SALT),
            session0Info,
            32
        );
        expect(bytesToHex(session0)).toBe(PSK_RATCHET_VECTORS.session0);

        // Session 1
        const session1Info = new Uint8Array(4);
        new DataView(session1Info.buffer).setUint32(0, 1, false); // big-endian
        const session1 = hkdf(
            sha256,
            initialPSK,
            new TextEncoder().encode(PSK_HKDF.SESSION_SALT),
            session1Info,
            32
        );
        expect(bytesToHex(session1)).toBe(PSK_RATCHET_VECTORS.session1);

        // Counter 0 = session 0, position 0
        const pos0Info = new Uint8Array(4); // all zeros = 0 big-endian
        const counter0 = hkdf(
            sha256,
            session0,
            new TextEncoder().encode(PSK_HKDF.POSITION_SALT),
            pos0Info,
            32
        );
        expect(bytesToHex(counter0)).toBe(PSK_RATCHET_VECTORS.counter0);

        // Counter 99 = session 0, position 99
        const pos99Info = new Uint8Array(4);
        new DataView(pos99Info.buffer).setUint32(0, 99, false);
        const counter99 = hkdf(
            sha256,
            session0,
            new TextEncoder().encode(PSK_HKDF.POSITION_SALT),
            pos99Info,
            32
        );
        expect(bytesToHex(counter99)).toBe(PSK_RATCHET_VECTORS.counter99);

        // Counter 100 = session 1, position 0
        const counter100 = hkdf(
            sha256,
            session1,
            new TextEncoder().encode(PSK_HKDF.POSITION_SALT),
            pos0Info,
            32
        );
        expect(bytesToHex(counter100)).toBe(PSK_RATCHET_VECTORS.counter100);

        console.log('  PSK ratchet vectors verified against reference');
    });
});

describe('cross-impl', () => {
    const messageKeys = Object.keys(TEST_MESSAGES).sort();
    const implementations = ['swift', 'ts', 'python', 'rust', 'kotlin'];

    // Only run this test if at least one implementation's envelope directory exists
    const hasAnyEnvelopes = implementations.some(impl => existsSync(`test-envelopes-${impl}`));

    test.skipIf(!hasAnyEnvelopes)('verify all implementations', () => {
        let totalPassed = 0;
        let totalFailed = 0;
        let totalSkipped = 0;

        for (const impl of implementations) {
            const envelopeDir = `test-envelopes-${impl}`;
            if (!existsSync(envelopeDir)) {
                console.log(`${impl}: SKIP - directory not found`);
                totalSkipped++;
                continue;
            }

            let passed = 0;
            let failed = 0;

            for (const key of messageKeys) {
                const envelopePath = `${envelopeDir}/${key}.hex`;
                if (!existsSync(envelopePath)) {
                    continue;
                }

                try {
                    const hexContent = readFileSync(envelopePath, 'utf-8').trim();
                    const encoded = hexToBytes(hexContent);
                    const envelope = decodeEnvelope(encoded);

                    const decrypted = decryptMessage(envelope, bobKeys.privateKey, bobKeys.publicKey);

                    if (decrypted && decrypted.text === TEST_MESSAGES[key]) {
                        passed++;
                    } else {
                        failed++;
                    }
                } catch {
                    failed++;
                }
            }

            console.log(`${impl}: ${passed}/${passed + failed} passed`);
            totalPassed += passed;
            totalFailed += failed;
        }

        console.log(`\nTotal: ${totalPassed} passed, ${totalFailed} failed, ${totalSkipped} impl(s) skipped`);
        expect(totalFailed).toBe(0);
    });
});
