/**
 * PSK Counter Validator — reference implementation
 *
 * Implements the counter validation rules from the AlgoChat PSK v1.1 protocol:
 *
 *   1. Reject replay: same counter value already seen
 *   2. Reject too far ahead: counter > highestSeen + COUNTER_WINDOW
 *   3. Reject too far behind: counter < highestSeen - COUNTER_WINDOW
 *      (only enforced after peer has sent > SESSION_SIZE messages)
 *   4. Accept any unseen counter within the window
 *
 * The validator tracks per-peer state using a sliding bitmap for efficient
 * replay detection within the counter window.
 */

import { PSK_PROTOCOL } from './test-vectors';

export type CounterResult =
    | { accepted: true }
    | { accepted: false; reason: 'replay' | 'too_far_ahead' | 'too_far_behind' };

export class PskCounterValidator {
    /** Highest counter value seen from this peer */
    private highestSeen: number = -1;

    /** Total number of messages accepted */
    private acceptedCount: number = 0;

    /** Bitmap tracking which counters have been seen within the window */
    private seenBitmap: Set<number> = new Set();

    /** Counter window size (default from protocol) */
    private readonly window: number;

    /** Session size threshold for enforcing lower bound (default from protocol) */
    private readonly sessionSize: number;

    constructor(
        window: number = PSK_PROTOCOL.COUNTER_WINDOW,
        sessionSize: number = PSK_PROTOCOL.SESSION_SIZE,
    ) {
        this.window = window;
        this.sessionSize = sessionSize;
    }

    /**
     * Validate and accept a counter value.
     * Returns whether the counter was accepted and the rejection reason if not.
     */
    validate(counter: number): CounterResult {
        // Rule 1: Reject replay
        if (this.seenBitmap.has(counter)) {
            return { accepted: false, reason: 'replay' };
        }

        // Rule 2: Reject too far ahead
        if (this.highestSeen >= 0 && counter > this.highestSeen + this.window) {
            return { accepted: false, reason: 'too_far_ahead' };
        }

        // Rule 3: Reject too far behind (only after enough messages)
        if (this.acceptedCount > this.sessionSize && this.highestSeen >= 0) {
            if (counter < this.highestSeen - this.window) {
                return { accepted: false, reason: 'too_far_behind' };
            }
        }

        // Accept: update state
        this.seenBitmap.add(counter);
        this.acceptedCount++;

        if (counter > this.highestSeen) {
            this.highestSeen = counter;
        }

        // Prune bitmap: remove entries far below the window
        this.pruneOldEntries();

        return { accepted: true };
    }

    /** Get the highest counter seen so far */
    getHighestSeen(): number {
        return this.highestSeen;
    }

    /** Get the total number of accepted messages */
    getAcceptedCount(): number {
        return this.acceptedCount;
    }

    /** Reset the validator state */
    reset(): void {
        this.highestSeen = -1;
        this.acceptedCount = 0;
        this.seenBitmap.clear();
    }

    /**
     * Prune seen entries that are far enough below the window
     * to no longer matter for replay detection.
     */
    private pruneOldEntries(): void {
        if (this.highestSeen < this.window) return;

        const cutoff = this.highestSeen - this.window - 1;
        for (const counter of this.seenBitmap) {
            if (counter < cutoff) {
                this.seenBitmap.delete(counter);
            }
        }
    }
}
