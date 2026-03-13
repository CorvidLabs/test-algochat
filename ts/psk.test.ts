/**
 * PSK v1.1 cross-implementation tests for AlgoChat
 *
 * Tests PSK ratchet derivation, envelope encoding/decoding,
 * encryption/decryption, and cross-implementation verification.
 */

import { describe, test, expect, beforeAll } from 'bun:test';
import { readFileSync, existsSync, writeFileSync, mkdirSync } from 'fs';
import {
    getAliceKeys,
    getBobKeys,
    TEST_MESSAGES as BASE_TEST_MESSAGES,
    PSK_PROTOCOL,
    PSK_RATCHET_VECTORS,
    PSK_HKDF,
    bytesToHex,
    hexToBytes,
    bytesEqual,
} from './test-vectors';

// PSK max payload is 878 (vs 882 for v1.0), so adjust max_payload test
const TEST_MESSAGES: Record<string, string> = {
    ...BASE_TEST_MESSAGES,
    max_payload: 'A'.repeat(PSK_PROTOCOL.MAX_PAYLOAD_SIZE),
};
import {
    pskEncryptMessage,
    pskDecryptMessage,
    encodePskEnvelope,
    decodePskEnvelope,
    isPskMessage,
    derivePskForCounter,
    PskEnvelope,
} from './psk-crypto';

// Shared test PSK (32 bytes of 0xBB — distinct from ratchet vector seed)
const TEST_PSK = hexToBytes('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb');

let aliceKeys: { privateKey: Uint8Array; publicKey: Uint8Array };
let bobKeys: { privateKey: Uint8Array; publicKey: Uint8Array };

beforeAll(() => {
    aliceKeys = getAliceKeys();
    bobKeys = getBobKeys();

    console.log('\n=== PSK v1.1 Test Suite ===');
    console.log(`Alice pubkey: ${bytesToHex(aliceKeys.publicKey)}`);
    console.log(`Bob pubkey:   ${bytesToHex(bobKeys.publicKey)}`);
    console.log(`Test PSK:     ${bytesToHex(TEST_PSK).substring(0, 16)}...`);
    console.log('');
});

describe('PSK Ratchet Derivation', () => {
    const ratchetPSK = hexToBytes(PSK_RATCHET_VECTORS.initialPSK);

    test('counter 0 matches reference vector', () => {
        const derived = derivePskForCounter(ratchetPSK, 0);
        expect(bytesToHex(derived)).toBe(PSK_RATCHET_VECTORS.counter0);
    });

    test('counter 99 matches reference vector', () => {
        const derived = derivePskForCounter(ratchetPSK, 99);
        expect(bytesToHex(derived)).toBe(PSK_RATCHET_VECTORS.counter99);
    });

    test('counter 100 matches reference vector (session boundary)', () => {
        const derived = derivePskForCounter(ratchetPSK, 100);
        expect(bytesToHex(derived)).toBe(PSK_RATCHET_VECTORS.counter100);
    });

    test('different counters produce different keys', () => {
        const key0 = derivePskForCounter(ratchetPSK, 0);
        const key1 = derivePskForCounter(ratchetPSK, 1);
        const key100 = derivePskForCounter(ratchetPSK, 100);
        expect(bytesEqual(key0, key1)).toBe(false);
        expect(bytesEqual(key0, key100)).toBe(false);
        expect(bytesEqual(key1, key100)).toBe(false);
    });

    test('same counter is deterministic', () => {
        const a = derivePskForCounter(ratchetPSK, 42);
        const b = derivePskForCounter(ratchetPSK, 42);
        expect(bytesEqual(a, b)).toBe(true);
    });
});

describe('PSK Envelope Encoding', () => {
    test('encodes envelope with correct 130-byte header', () => {
        const envelope = pskEncryptMessage(
            'test',
            aliceKeys.privateKey,
            aliceKeys.publicKey,
            bobKeys.publicKey,
            TEST_PSK,
            0,
        );

        const encoded = encodePskEnvelope(envelope);

        // Check header size
        expect(encoded.length).toBeGreaterThanOrEqual(PSK_PROTOCOL.HEADER_SIZE + PSK_PROTOCOL.TAG_SIZE);

        // Check version and protocol
        expect(encoded[0]).toBe(0x01);
        expect(encoded[1]).toBe(PSK_PROTOCOL.PROTOCOL_ID); // 0x02

        // Check counter at offset 2-5
        const counter = new DataView(encoded.buffer, encoded.byteOffset).getUint32(2, false);
        expect(counter).toBe(0);
    });

    test('counter is correctly encoded in big-endian', () => {
        const envelope = pskEncryptMessage(
            'test',
            aliceKeys.privateKey,
            aliceKeys.publicKey,
            bobKeys.publicKey,
            TEST_PSK,
            256,
        );

        const encoded = encodePskEnvelope(envelope);
        const counter = new DataView(encoded.buffer, encoded.byteOffset).getUint32(2, false);
        expect(counter).toBe(256);
    });

    test('encode/decode roundtrip preserves all fields', () => {
        const envelope = pskEncryptMessage(
            'roundtrip test',
            aliceKeys.privateKey,
            aliceKeys.publicKey,
            bobKeys.publicKey,
            TEST_PSK,
            42,
        );

        const encoded = encodePskEnvelope(envelope);
        const decoded = decodePskEnvelope(encoded);

        expect(decoded.version).toBe(envelope.version);
        expect(decoded.protocolId).toBe(envelope.protocolId);
        expect(decoded.ratchetCounter).toBe(42);
        expect(bytesEqual(decoded.senderPublicKey, envelope.senderPublicKey)).toBe(true);
        expect(bytesEqual(decoded.ephemeralPublicKey, envelope.ephemeralPublicKey)).toBe(true);
        expect(bytesEqual(decoded.nonce, envelope.nonce)).toBe(true);
        expect(bytesEqual(decoded.encryptedSenderKey, envelope.encryptedSenderKey)).toBe(true);
        expect(bytesEqual(decoded.ciphertext, envelope.ciphertext)).toBe(true);
    });

    test('isPskMessage detects valid PSK envelopes', () => {
        const envelope = pskEncryptMessage(
            'detect me',
            aliceKeys.privateKey,
            aliceKeys.publicKey,
            bobKeys.publicKey,
            TEST_PSK,
            0,
        );
        const encoded = encodePskEnvelope(envelope);

        expect(isPskMessage(encoded)).toBe(true);

        // Standard v1.0 should not be detected as PSK
        const fakeV1 = new Uint8Array(200);
        fakeV1[0] = 0x01;
        fakeV1[1] = 0x01; // protocol v1
        expect(isPskMessage(fakeV1)).toBe(false);

        // Too short
        expect(isPskMessage(new Uint8Array([0x01, 0x02]))).toBe(false);
    });
});

describe('PSK Encryption/Decryption', () => {
    test('encrypt/decrypt roundtrip', () => {
        const envelope = pskEncryptMessage(
            'Hello PSK!',
            aliceKeys.privateKey,
            aliceKeys.publicKey,
            bobKeys.publicKey,
            TEST_PSK,
            0,
        );

        const decrypted = pskDecryptMessage(envelope, bobKeys.privateKey, bobKeys.publicKey, TEST_PSK);
        expect(decrypted).toBe('Hello PSK!');
    });

    test('sender can decrypt own message (bidirectional)', () => {
        const envelope = pskEncryptMessage(
            'bidirectional PSK',
            aliceKeys.privateKey,
            aliceKeys.publicKey,
            bobKeys.publicKey,
            TEST_PSK,
            5,
        );

        const decrypted = pskDecryptMessage(envelope, aliceKeys.privateKey, aliceKeys.publicKey, TEST_PSK);
        expect(decrypted).toBe('bidirectional PSK');
    });

    test('works across session boundary (counter 99 → 100)', () => {
        const msg99 = pskEncryptMessage(
            'before boundary',
            aliceKeys.privateKey,
            aliceKeys.publicKey,
            bobKeys.publicKey,
            TEST_PSK,
            99,
        );
        const msg100 = pskEncryptMessage(
            'after boundary',
            aliceKeys.privateKey,
            aliceKeys.publicKey,
            bobKeys.publicKey,
            TEST_PSK,
            100,
        );

        expect(pskDecryptMessage(msg99, bobKeys.privateKey, bobKeys.publicKey, TEST_PSK)).toBe('before boundary');
        expect(pskDecryptMessage(msg100, bobKeys.privateKey, bobKeys.publicKey, TEST_PSK)).toBe('after boundary');
    });

    test('wrong PSK fails to decrypt', () => {
        const envelope = pskEncryptMessage(
            'secret',
            aliceKeys.privateKey,
            aliceKeys.publicKey,
            bobKeys.publicKey,
            TEST_PSK,
            0,
        );

        const wrongPSK = hexToBytes('cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc');
        expect(() => {
            pskDecryptMessage(envelope, bobKeys.privateKey, bobKeys.publicKey, wrongPSK);
        }).toThrow();
    });

    test('wrong counter fails to decrypt', () => {
        const envelope = pskEncryptMessage(
            'secret',
            aliceKeys.privateKey,
            aliceKeys.publicKey,
            bobKeys.publicKey,
            TEST_PSK,
            0,
        );

        // Tamper with counter
        const tampered = { ...envelope, ratchetCounter: 1 };
        expect(() => {
            pskDecryptMessage(tampered, bobKeys.privateKey, bobKeys.publicKey, TEST_PSK);
        }).toThrow();
    });

    test('handles unicode messages', () => {
        const envelope = pskEncryptMessage(
            'Hello 👋 PSK 🔐',
            aliceKeys.privateKey,
            aliceKeys.publicKey,
            bobKeys.publicKey,
            TEST_PSK,
            0,
        );

        const decrypted = pskDecryptMessage(envelope, bobKeys.privateKey, bobKeys.publicKey, TEST_PSK);
        expect(decrypted).toBe('Hello 👋 PSK 🔐');
    });
});

describe('PSK Envelope via Wire Format', () => {
    test('encrypt → encode → decode → decrypt roundtrip', () => {
        const envelope = pskEncryptMessage(
            'wire format test',
            aliceKeys.privateKey,
            aliceKeys.publicKey,
            bobKeys.publicKey,
            TEST_PSK,
            7,
        );

        const encoded = encodePskEnvelope(envelope);
        const decoded = decodePskEnvelope(encoded);
        const decrypted = pskDecryptMessage(decoded, bobKeys.privateKey, bobKeys.publicKey, TEST_PSK);

        expect(decrypted).toBe('wire format test');
    });
});

describe('PSK Multi-Message Tests', () => {
    const messageKeys = Object.keys(TEST_MESSAGES).sort();

    test('all message types encrypt/decrypt correctly', () => {
        let passed = 0;
        let failed = 0;

        for (let i = 0; i < messageKeys.length; i++) {
            const key = messageKeys[i];
            const message = TEST_MESSAGES[key];

            try {
                const envelope = pskEncryptMessage(
                    message,
                    aliceKeys.privateKey,
                    aliceKeys.publicKey,
                    bobKeys.publicKey,
                    TEST_PSK,
                    i, // Use index as counter
                );

                const decrypted = pskDecryptMessage(envelope, bobKeys.privateKey, bobKeys.publicKey, TEST_PSK);
                expect(decrypted).toBe(message);
                passed++;

                const display = message.length > 30 ? message.substring(0, 30) + '...' : message;
                console.log(`  ✓ ${key} (counter=${i}): "${display.replace(/\n/g, '\\n')}"`);
            } catch (error) {
                failed++;
                console.log(`  ✗ ${key} (counter=${i}): FAILED - ${error}`);
            }
        }

        console.log(`  PSK multi-message: ${passed}/${messageKeys.length} passed`);
        expect(failed).toBe(0);
    });

    test('export all PSK envelopes to test-envelopes-ts-psk/', () => {
        const outputDir = 'test-envelopes-ts-psk';
        mkdirSync(outputDir, { recursive: true });

        let exportCount = 0;

        for (let i = 0; i < messageKeys.length; i++) {
            const key = messageKeys[i];
            const message = TEST_MESSAGES[key];

            const envelope = pskEncryptMessage(
                message,
                aliceKeys.privateKey,
                aliceKeys.publicKey,
                bobKeys.publicKey,
                TEST_PSK,
                i,
            );

            const encoded = encodePskEnvelope(envelope);
            writeFileSync(`${outputDir}/${key}.hex`, bytesToHex(encoded));
            exportCount++;
        }

        // Write metadata for other implementations
        writeFileSync(`${outputDir}/metadata.json`, JSON.stringify({
            pskHex: bytesToHex(TEST_PSK),
            counterStart: 0,
            messageOrder: messageKeys,
            implementation: 'typescript',
            protocolVersion: '1.1',
        }, null, 2));

        console.log(`  Exported ${exportCount} PSK envelopes to ${outputDir}/`);
    });
});

describe('PSK Cross-Implementation Verification', () => {
    const messageKeys = Object.keys(TEST_MESSAGES).sort();
    const implementations = ['swift', 'ts', 'python', 'rust', 'kotlin'];

    for (const impl of implementations) {
        const pskDir = `test-envelopes-${impl}-psk`;

        test.skipIf(!existsSync(pskDir))(`decrypt all ${impl} PSK envelopes`, () => {
            // Read metadata to get the PSK used
            let psk = TEST_PSK;
            const metaPath = `${pskDir}/metadata.json`;
            if (existsSync(metaPath)) {
                const meta = JSON.parse(readFileSync(metaPath, 'utf-8'));
                if (meta.pskHex) {
                    psk = hexToBytes(meta.pskHex);
                }
            }

            let passed = 0;
            let failed = 0;
            let skipped = 0;

            for (const key of messageKeys) {
                const envelopePath = `${pskDir}/${key}.hex`;
                if (!existsSync(envelopePath)) {
                    skipped++;
                    continue;
                }

                try {
                    const hexContent = readFileSync(envelopePath, 'utf-8').trim();
                    const encoded = hexToBytes(hexContent);

                    expect(isPskMessage(encoded)).toBe(true);

                    const envelope = decodePskEnvelope(encoded);
                    const decrypted = pskDecryptMessage(
                        envelope,
                        bobKeys.privateKey,
                        bobKeys.publicKey,
                        psk,
                    );

                    expect(decrypted).toBe(TEST_MESSAGES[key]);
                    passed++;
                } catch (error) {
                    failed++;
                    console.log(`  ✗ ${impl}/${key}: FAILED - ${error}`);
                }
            }

            console.log(`  ${impl} PSK cross-impl: ${passed} passed, ${failed} failed, ${skipped} skipped`);
            expect(failed).toBe(0);
        });
    }
});

describe('psk-cross-impl', () => {
    const messageKeys = Object.keys(TEST_MESSAGES).sort();
    const implementations = ['swift', 'ts', 'python', 'rust', 'kotlin'];

    const hasAnyPskEnvelopes = implementations.some(impl => existsSync(`test-envelopes-${impl}-psk`));

    test.skipIf(!hasAnyPskEnvelopes)('verify all PSK implementations', () => {
        let totalPassed = 0;
        let totalFailed = 0;
        let totalSkipped = 0;

        for (const impl of implementations) {
            const pskDir = `test-envelopes-${impl}-psk`;
            if (!existsSync(pskDir)) {
                console.log(`${impl}: SKIP - PSK directory not found`);
                totalSkipped++;
                continue;
            }

            let psk = TEST_PSK;
            const metaPath = `${pskDir}/metadata.json`;
            if (existsSync(metaPath)) {
                const meta = JSON.parse(readFileSync(metaPath, 'utf-8'));
                if (meta.pskHex) psk = hexToBytes(meta.pskHex);
            }

            let passed = 0;
            let failed = 0;

            for (const key of messageKeys) {
                const envelopePath = `${pskDir}/${key}.hex`;
                if (!existsSync(envelopePath)) continue;

                try {
                    const hexContent = readFileSync(envelopePath, 'utf-8').trim();
                    const encoded = hexToBytes(hexContent);
                    const envelope = decodePskEnvelope(encoded);
                    const decrypted = pskDecryptMessage(envelope, bobKeys.privateKey, bobKeys.publicKey, psk);

                    if (decrypted === TEST_MESSAGES[key]) {
                        passed++;
                    } else {
                        failed++;
                    }
                } catch {
                    failed++;
                }
            }

            console.log(`${impl}: ${passed}/${passed + failed} PSK envelopes verified`);
            totalPassed += passed;
            totalFailed += failed;
        }

        console.log(`\nPSK Total: ${totalPassed} passed, ${totalFailed} failed, ${totalSkipped} impl(s) skipped`);
        expect(totalFailed).toBe(0);
    });
});
