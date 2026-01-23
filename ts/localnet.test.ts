/**
 * Localnet integration tests for AlgoChat
 *
 * Tests end-to-end message reading (cross-implementation verification).
 * Note: Actual blockchain sending requires valid Algorand accounts.
 */

import { describe, test, expect, beforeAll } from 'bun:test';
import { decryptMessage, decodeEnvelope, isChatMessage } from 'ts-algochat';
import {
    getAliceKeys,
    getBobKeys,
    SIMPLE_MESSAGE,
    bytesToHex,
    hexToBytes,
} from './test-vectors';
import { readFileSync, existsSync } from 'fs';

// Keys (computed in beforeAll)
let aliceKeys: { privateKey: Uint8Array; publicKey: Uint8Array };
let bobKeys: { privateKey: Uint8Array; publicKey: Uint8Array };

beforeAll(() => {
    aliceKeys = getAliceKeys();
    bobKeys = getBobKeys();

    console.log('\n=== TypeScript Localnet Tests ===');
    console.log('Note: These tests verify cross-implementation compatibility');
    console.log('');
});

describe('Cross-Implementation Verification', () => {
    test('decrypts Swift envelope', () => {
        const swiftEnvelopePath = 'test-envelope-swift.hex';
        if (!existsSync(swiftEnvelopePath)) {
            console.log('  SKIP: Run Swift tests first to generate envelope');
            return;
        }

        const hexContent = readFileSync(swiftEnvelopePath, 'utf-8').trim();
        const encoded = hexToBytes(hexContent);

        expect(isChatMessage(encoded)).toBe(true);

        const envelope = decodeEnvelope(encoded);
        console.log(`  Swift envelope: ${encoded.length} bytes`);
        console.log(`  Sender pubkey: ${bytesToHex(envelope.senderPublicKey)}`);

        // Verify the sender is Alice
        expect(bytesToHex(envelope.senderPublicKey)).toBe(bytesToHex(aliceKeys.publicKey));

        // Decrypt as Bob
        const decrypted = decryptMessage(envelope, bobKeys.privateKey, bobKeys.publicKey);

        expect(decrypted).not.toBeNull();
        expect(decrypted!.text).toBe(SIMPLE_MESSAGE);
        console.log(`  Decrypted: "${decrypted!.text}"`);
    });

    test('key derivation matches Swift', () => {
        const vectorsPath = 'test-envelope-swift.txt';
        if (!existsSync(vectorsPath)) {
            console.log('  SKIP: Run Swift tests first to generate vectors');
            return;
        }

        const content = readFileSync(vectorsPath, 'utf-8');

        // Extract sender public key from Swift output
        const senderPubKeyMatch = content.match(/senderPubKey: ([a-f0-9]+)/);
        if (senderPubKeyMatch) {
            const swiftAlicePubKey = senderPubKeyMatch[1];
            const tsAlicePubKey = bytesToHex(aliceKeys.publicKey);

            console.log(`  Swift Alice pubkey: ${swiftAlicePubKey}`);
            console.log(`  TS Alice pubkey:    ${tsAlicePubKey}`);

            expect(tsAlicePubKey).toBe(swiftAlicePubKey);
        }
    });
});
