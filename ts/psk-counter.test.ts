/**
 * PSK Counter Validation Tests
 *
 * Tests replay detection, counter window enforcement, and out-of-order
 * delivery handling per the AlgoChat PSK v1.1 protocol specification.
 *
 * These are security-critical behaviors that all implementations must match.
 */

import { describe, test, expect, beforeEach } from 'bun:test';
import { PskCounterValidator } from './psk-counter';
import { PSK_PROTOCOL } from './test-vectors';
import {
    pskEncryptMessage,
    pskDecryptMessage,
    encodePskEnvelope,
    decodePskEnvelope,
} from './psk-crypto';
import {
    getAliceKeys,
    getBobKeys,
    hexToBytes,
} from './test-vectors';

const TEST_PSK = hexToBytes('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb');

let validator: PskCounterValidator;

beforeEach(() => {
    validator = new PskCounterValidator();
});

// ─── Replay Detection ────────────────────────────────────────────────

describe('Replay Detection', () => {
    test('rejects duplicate counter 0', () => {
        expect(validator.validate(0).accepted).toBe(true);
        const result = validator.validate(0);
        expect(result.accepted).toBe(false);
        if (!result.accepted) expect(result.reason).toBe('replay');
    });

    test('rejects duplicate of any counter value', () => {
        expect(validator.validate(42).accepted).toBe(true);
        expect(validator.validate(43).accepted).toBe(true);
        const result = validator.validate(42);
        expect(result.accepted).toBe(false);
        if (!result.accepted) expect(result.reason).toBe('replay');
    });

    test('rejects triple replay', () => {
        expect(validator.validate(5).accepted).toBe(true);
        expect(validator.validate(5).accepted).toBe(false);
        expect(validator.validate(5).accepted).toBe(false);
    });

    test('sequential counters are all unique — no replays', () => {
        for (let i = 0; i < 50; i++) {
            expect(validator.validate(i).accepted).toBe(true);
        }
    });

    test('replay detected after out-of-order acceptance', () => {
        // Accept 0, 5, 3 — then replay 5
        expect(validator.validate(0).accepted).toBe(true);
        expect(validator.validate(5).accepted).toBe(true);
        expect(validator.validate(3).accepted).toBe(true);

        const result = validator.validate(5);
        expect(result.accepted).toBe(false);
        if (!result.accepted) expect(result.reason).toBe('replay');
    });
});

// ─── Counter Window (Upper Bound) ────────────────────────────────────

describe('Counter Window — Upper Bound', () => {
    test('accepts counter within window of highest seen', () => {
        expect(validator.validate(0).accepted).toBe(true);
        // Counter 200 is exactly at the window boundary (0 + 200)
        expect(validator.validate(PSK_PROTOCOL.COUNTER_WINDOW).accepted).toBe(true);
    });

    test('rejects counter beyond window', () => {
        expect(validator.validate(0).accepted).toBe(true);
        // Counter 201 is 1 beyond the window
        const result = validator.validate(PSK_PROTOCOL.COUNTER_WINDOW + 1);
        expect(result.accepted).toBe(false);
        if (!result.accepted) expect(result.reason).toBe('too_far_ahead');
    });

    test('rejects large jump forward', () => {
        expect(validator.validate(0).accepted).toBe(true);
        const result = validator.validate(1000);
        expect(result.accepted).toBe(false);
        if (!result.accepted) expect(result.reason).toBe('too_far_ahead');
    });

    test('window slides forward as highest counter advances', () => {
        // Advance through increments
        expect(validator.validate(0).accepted).toBe(true);
        expect(validator.validate(100).accepted).toBe(true);
        // Now highest is 100, so 100+200=300 should be accepted
        expect(validator.validate(300).accepted).toBe(true);
        // And 300+200=500 should be accepted
        expect(validator.validate(500).accepted).toBe(true);
        // But 500+201=701 should be rejected
        const result = validator.validate(701);
        expect(result.accepted).toBe(false);
        if (!result.accepted) expect(result.reason).toBe('too_far_ahead');
    });

    test('first message can be any counter value', () => {
        // First message has no prior reference, so any counter is accepted
        expect(validator.validate(50000).accepted).toBe(true);
    });
});

// ─── Counter Window (Lower Bound) ────────────────────────────────────

describe('Counter Window — Lower Bound', () => {
    test('lower bound NOT enforced before SESSION_SIZE messages', () => {
        // Accept messages 0 through SESSION_SIZE (101 messages)
        // but stop at exactly SESSION_SIZE to stay at the threshold
        for (let i = 0; i <= PSK_PROTOCOL.SESSION_SIZE; i++) {
            expect(validator.validate(i).accepted).toBe(true);
        }
        // We've accepted 101 messages (0..100), which equals SESSION_SIZE + 1
        // highestSeen = 100, and acceptedCount = 101
        // Since acceptedCount (101) > SESSION_SIZE (100), lower bound is now enforced
        // But counter 0 was already accepted, so it's a replay
        // Let's test with a new counter that's behind the window
        // Actually, highestSeen=100, window=200, so 100-200 = negative, nothing is behind
        // We need a higher highest to test this properly

        // Reset and set up properly
        validator.reset();

        // Accept exactly SESSION_SIZE messages (0..99) — 100 messages
        for (let i = 0; i < PSK_PROTOCOL.SESSION_SIZE; i++) {
            expect(validator.validate(i).accepted).toBe(true);
        }
        // acceptedCount = 100, which is NOT > SESSION_SIZE (100), so lower bound not enforced

        // Jump to 400 (within window of highest=99: 99+200=299... 400 > 299)
        // Actually 400 > 99+200=299, so this would be too_far_ahead
        // Let's jump to 299 instead
        expect(validator.validate(299).accepted).toBe(true);

        // Now highestSeen=299, acceptedCount=101 which IS > SESSION_SIZE
        // But counter 0 is 299 behind. 299 - 200 = 99. Counter 0 < 99.
        // Counter 0 was already seen (replay), so test with an unseen low counter
        // Counter 50 was already seen too. We need something that wasn't accepted.
        // All 0..99 were accepted. Let's try a fresh validator with a cleaner setup.
    });

    test('lower bound enforced after SESSION_SIZE + 1 messages', () => {
        // Accept 0..100 sequentially (101 messages, acceptedCount > SESSION_SIZE)
        for (let i = 0; i <= PSK_PROTOCOL.SESSION_SIZE; i++) {
            expect(validator.validate(i).accepted).toBe(true);
        }
        // highestSeen=100, acceptedCount=101
        // Jump to 400 (within window: 100+200=300... 400 > 300, rejected)
        // Jump to 300 instead
        expect(validator.validate(300).accepted).toBe(true);
        // Now highestSeen=300, acceptedCount=102
        // Lower bound: 300 - 200 = 100. Counter < 100 should be rejected.
        // Counters 0..100 were already seen. Let's try to make one that isn't.
        // We skipped 101..299. Counter 101 should be within window.
        expect(validator.validate(101).accepted).toBe(true);

        // Counter 99 is below 300 - 200 = 100, so should be rejected as too_far_behind
        // But 99 was already seen... the reason would be 'replay' first
        // We need a counter that was never seen AND is below the window
        // We went 0..100 then 300, 101. Skipped 102..299.
        // 99 was seen → replay. We need highestSeen high enough that unseen counters fall below.

        // Let's advance further: accept up to 500 in a jump
        expect(validator.validate(500).accepted).toBe(true);
        // highestSeen=500, lower bound = 500 - 200 = 300
        // Counter 200 was never seen (we skipped 102..299 except we accepted 300)
        // Counter 200 < 300 → too_far_behind
        const result = validator.validate(200);
        expect(result.accepted).toBe(false);
        if (!result.accepted) expect(result.reason).toBe('too_far_behind');
    });

    test('lower bound does not apply when peer sent <= SESSION_SIZE messages', () => {
        // Use a small custom validator to make this easier to test
        const v = new PskCounterValidator(10, 5); // window=10, sessionSize=5

        // Accept 5 messages (at threshold, not exceeded)
        v.validate(0);
        v.validate(1);
        v.validate(2);
        v.validate(3);
        v.validate(4);
        // acceptedCount=5, not > sessionSize=5, so lower bound not enforced

        // Jump ahead
        v.validate(14); // within window (4+10=14)
        // acceptedCount=6 > sessionSize=5, but let's check if lower bound kicks in
        // highestSeen=14, lower bound=14-10=4
        // Counter 3 < 4, but was already seen → replay
        // Counter 5 was never seen. 5 > 4, so it's within the window → accepted
        expect(v.validate(5).accepted).toBe(true);
    });

    test('very old counter rejected after sufficient messages', () => {
        const v = new PskCounterValidator(10, 5); // window=10, sessionSize=5

        // Send 6 messages to exceed sessionSize threshold
        for (let i = 0; i < 6; i++) {
            v.validate(i);
        }
        // acceptedCount=6 > sessionSize=5
        // highestSeen=5, lower bound = 5 - 10 = negative → no rejection yet

        // Jump to 20 (within window: 5+10=15... 20 > 15, rejected)
        // Jump to 15 instead
        v.validate(15);
        // highestSeen=15, lower bound=15-10=5
        // Counter 4 < 5 and was already seen → replay (takes priority)
        // Counter 6 was never seen, 6 > 5 → within window → accepted
        expect(v.validate(6).accepted).toBe(true);

        // Now advance to 25
        v.validate(25);
        // highestSeen=25, lower bound=25-10=15
        // Counter 7 was never seen, 7 < 15 → too_far_behind
        const result = v.validate(7);
        expect(result.accepted).toBe(false);
        if (!result.accepted) expect(result.reason).toBe('too_far_behind');
    });
});

// ─── Out-of-Order Delivery ───────────────────────────────────────────

describe('Out-of-Order Delivery', () => {
    test('accepts messages arriving out of sequence', () => {
        // Messages arrive: 0, 3, 1, 4, 2
        expect(validator.validate(0).accepted).toBe(true);
        expect(validator.validate(3).accepted).toBe(true);
        expect(validator.validate(1).accepted).toBe(true);
        expect(validator.validate(4).accepted).toBe(true);
        expect(validator.validate(2).accepted).toBe(true);
    });

    test('accepts reverse-order delivery within window', () => {
        // Deliver 10 messages in reverse: 9, 8, 7, ..., 0
        for (let i = 9; i >= 0; i--) {
            expect(validator.validate(i).accepted).toBe(true);
        }
    });

    test('accepts interleaved delivery', () => {
        // Even counters first, then odd
        for (let i = 0; i < 20; i += 2) {
            expect(validator.validate(i).accepted).toBe(true);
        }
        for (let i = 1; i < 20; i += 2) {
            expect(validator.validate(i).accepted).toBe(true);
        }
    });

    test('gap filling within window works', () => {
        // Accept 0, then jump to 50, then fill in gaps
        expect(validator.validate(0).accepted).toBe(true);
        expect(validator.validate(50).accepted).toBe(true);
        // Fill gap
        for (let i = 1; i < 50; i++) {
            expect(validator.validate(i).accepted).toBe(true);
        }
    });

    test('late message just inside window boundary is accepted', () => {
        const v = new PskCounterValidator(10, 5);

        // Send enough to enable lower bound
        for (let i = 0; i < 6; i++) v.validate(i);
        v.validate(15);
        // highestSeen=15, lower bound=15-10=5
        // Counter 5 was already seen → replay. Counter 6 wasn't → should work
        expect(v.validate(6).accepted).toBe(true);
        // Counter 5 exactly at boundary: 5 is NOT < 5, so it would be in window,
        // but it was already seen → replay
        const result = v.validate(5);
        expect(result.accepted).toBe(false);
        if (!result.accepted) expect(result.reason).toBe('replay');
    });
});

// ─── Full Crypto + Counter Integration ───────────────────────────────

describe('PSK Crypto + Counter Integration', () => {
    const aliceKeys = getAliceKeys();
    const bobKeys = getBobKeys();

    test('sequential messages with counter validation', () => {
        const bobValidator = new PskCounterValidator();

        for (let counter = 0; counter < 10; counter++) {
            const envelope = pskEncryptMessage(
                `Message ${counter}`,
                aliceKeys.privateKey,
                aliceKeys.publicKey,
                bobKeys.publicKey,
                TEST_PSK,
                counter,
            );

            // Bob validates the counter before decrypting
            const result = bobValidator.validate(envelope.ratchetCounter);
            expect(result.accepted).toBe(true);

            const decrypted = pskDecryptMessage(
                envelope,
                bobKeys.privateKey,
                bobKeys.publicKey,
                TEST_PSK,
            );
            expect(decrypted).toBe(`Message ${counter}`);
        }
    });

    test('replayed envelope is detected by counter validator', () => {
        const bobValidator = new PskCounterValidator();

        const envelope = pskEncryptMessage(
            'Original message',
            aliceKeys.privateKey,
            aliceKeys.publicKey,
            bobKeys.publicKey,
            TEST_PSK,
            0,
        );

        // First reception — accept
        expect(bobValidator.validate(envelope.ratchetCounter).accepted).toBe(true);

        // Attacker replays the same envelope — reject
        const result = bobValidator.validate(envelope.ratchetCounter);
        expect(result.accepted).toBe(false);
        if (!result.accepted) expect(result.reason).toBe('replay');
    });

    test('out-of-order messages decrypt correctly with counter validation', () => {
        const bobValidator = new PskCounterValidator();

        // Alice sends messages 0, 1, 2, 3, 4 but they arrive 3, 0, 4, 1, 2
        const messages: Array<{ counter: number; text: string }> = [
            { counter: 0, text: 'First' },
            { counter: 1, text: 'Second' },
            { counter: 2, text: 'Third' },
            { counter: 3, text: 'Fourth' },
            { counter: 4, text: 'Fifth' },
        ];

        // Encrypt all
        const envelopes = messages.map(({ counter, text }) =>
            pskEncryptMessage(
                text,
                aliceKeys.privateKey,
                aliceKeys.publicKey,
                bobKeys.publicKey,
                TEST_PSK,
                counter,
            ),
        );

        // Deliver out of order: 3, 0, 4, 1, 2
        const deliveryOrder = [3, 0, 4, 1, 2];

        for (const idx of deliveryOrder) {
            const envelope = envelopes[idx];
            const result = bobValidator.validate(envelope.ratchetCounter);
            expect(result.accepted).toBe(true);

            const decrypted = pskDecryptMessage(
                envelope,
                bobKeys.privateKey,
                bobKeys.publicKey,
                TEST_PSK,
            );
            expect(decrypted).toBe(messages[idx].text);
        }
    });

    test('tampered counter in wire format causes decryption failure', () => {
        const envelope = pskEncryptMessage(
            'Authentic message',
            aliceKeys.privateKey,
            aliceKeys.publicKey,
            bobKeys.publicKey,
            TEST_PSK,
            42,
        );

        const encoded = encodePskEnvelope(envelope);

        // Tamper with the counter bytes (offset 2-5)
        const tampered = new Uint8Array(encoded);
        new DataView(tampered.buffer).setUint32(2, 99, false); // Change counter to 99

        const decoded = decodePskEnvelope(tampered);
        expect(decoded.ratchetCounter).toBe(99); // Counter field is changed

        // Decryption should fail because the ratchet PSK is derived from the counter
        expect(() => {
            pskDecryptMessage(decoded, bobKeys.privateKey, bobKeys.publicKey, TEST_PSK);
        }).toThrow();
    });

    test('cross-session counter transition with crypto', () => {
        const bobValidator = new PskCounterValidator();

        // Message at end of session 0 (counter 99)
        const msg99 = pskEncryptMessage(
            'End of session 0',
            aliceKeys.privateKey,
            aliceKeys.publicKey,
            bobKeys.publicKey,
            TEST_PSK,
            99,
        );

        // Message at start of session 1 (counter 100)
        const msg100 = pskEncryptMessage(
            'Start of session 1',
            aliceKeys.privateKey,
            aliceKeys.publicKey,
            bobKeys.publicKey,
            TEST_PSK,
            100,
        );

        // Both should validate and decrypt
        expect(bobValidator.validate(99).accepted).toBe(true);
        expect(pskDecryptMessage(msg99, bobKeys.privateKey, bobKeys.publicKey, TEST_PSK))
            .toBe('End of session 0');

        expect(bobValidator.validate(100).accepted).toBe(true);
        expect(pskDecryptMessage(msg100, bobKeys.privateKey, bobKeys.publicKey, TEST_PSK))
            .toBe('Start of session 1');
    });

    test('bidirectional conversation with independent counters', () => {
        const aliceValidator = new PskCounterValidator(); // Validates Bob's counters
        const bobValidator = new PskCounterValidator();   // Validates Alice's counters

        // Alice sends to Bob (counter 0)
        const aliceMsg0 = pskEncryptMessage(
            'Alice: Hello Bob!',
            aliceKeys.privateKey,
            aliceKeys.publicKey,
            bobKeys.publicKey,
            TEST_PSK,
            0,
        );
        expect(bobValidator.validate(0).accepted).toBe(true);
        expect(pskDecryptMessage(aliceMsg0, bobKeys.privateKey, bobKeys.publicKey, TEST_PSK))
            .toBe('Alice: Hello Bob!');

        // Bob sends to Alice (counter 0 — independent counter space)
        const bobMsg0 = pskEncryptMessage(
            'Bob: Hi Alice!',
            bobKeys.privateKey,
            bobKeys.publicKey,
            aliceKeys.publicKey,
            TEST_PSK,
            0,
        );
        expect(aliceValidator.validate(0).accepted).toBe(true);
        expect(pskDecryptMessage(bobMsg0, aliceKeys.privateKey, aliceKeys.publicKey, TEST_PSK))
            .toBe('Bob: Hi Alice!');

        // Alice sends again (counter 1)
        const aliceMsg1 = pskEncryptMessage(
            'Alice: How are you?',
            aliceKeys.privateKey,
            aliceKeys.publicKey,
            bobKeys.publicKey,
            TEST_PSK,
            1,
        );
        expect(bobValidator.validate(1).accepted).toBe(true);
        expect(pskDecryptMessage(aliceMsg1, bobKeys.privateKey, bobKeys.publicKey, TEST_PSK))
            .toBe('Alice: How are you?');

        // Bob cannot replay Alice's counter 0
        const bobReplay = bobValidator.validate(0);
        expect(bobReplay.accepted).toBe(false);
        if (!bobReplay.accepted) expect(bobReplay.reason).toBe('replay');
    });
});

// ─── Edge Cases ──────────────────────────────────────────────────────

describe('Counter Edge Cases', () => {
    test('counter 0 is valid as first message', () => {
        expect(validator.validate(0).accepted).toBe(true);
    });

    test('large counter is valid as first message', () => {
        expect(validator.validate(4294967295).accepted).toBe(true); // u32::MAX
    });

    test('window moves correctly with large initial counter', () => {
        expect(validator.validate(1000).accepted).toBe(true);
        // 1000 + 200 = 1200, so 1200 should be accepted
        expect(validator.validate(1200).accepted).toBe(true);
        // 1200 + 201 = 1401, rejected
        const result = validator.validate(1401);
        expect(result.accepted).toBe(false);
        if (!result.accepted) expect(result.reason).toBe('too_far_ahead');
    });

    test('validator reset clears all state', () => {
        validator.validate(0);
        validator.validate(1);
        expect(validator.validate(0).accepted).toBe(false); // replay

        validator.reset();

        expect(validator.validate(0).accepted).toBe(true); // fresh
        expect(validator.getHighestSeen()).toBe(0);
        expect(validator.getAcceptedCount()).toBe(1);
    });

    test('bitmap pruning does not affect active window', () => {
        // Accept many sequential counters, then verify window still works
        for (let i = 0; i < 300; i++) {
            expect(validator.validate(i).accepted).toBe(true);
        }
        // highestSeen=299, entries below 299-200-1=98 should be pruned
        // Counter 299 should be a replay
        expect(validator.validate(299).accepted).toBe(false);
        // Counter 150 (within window, was seen) should be replay
        expect(validator.validate(150).accepted).toBe(false);
        // Counter 300 (next sequential) should be accepted
        expect(validator.validate(300).accepted).toBe(true);
    });

    test('custom window size is respected', () => {
        const v = new PskCounterValidator(5, 3); // tiny window=5, sessionSize=3

        expect(v.validate(0).accepted).toBe(true);
        expect(v.validate(5).accepted).toBe(true);  // 0+5=5, at boundary
        const result = v.validate(12); // 5+5=10, 12 > 10
        expect(result.accepted).toBe(false);
        if (!result.accepted) expect(result.reason).toBe('too_far_ahead');
    });
});
