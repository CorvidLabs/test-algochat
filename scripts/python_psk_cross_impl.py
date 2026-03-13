#!/usr/bin/env python3
"""Cross-implementation PSK envelope generation and verification for AlgoChat v1.1."""

import json
import os
import sys

from algochat import (
    derive_keys_from_seed,
    encrypt_psk_message,
    encode_psk_envelope,
    decrypt_psk_message,
    decode_psk_envelope,
    is_psk_message,
    derive_psk_at_counter,
)
from algochat.keys import public_key_from_bytes, public_key_to_bytes

ALICE_SEED = bytes.fromhex(
    "0000000000000000000000000000000000000000000000000000000000000001"
)
BOB_SEED = bytes.fromhex(
    "0000000000000000000000000000000000000000000000000000000000000002"
)

# Shared test PSK (must match TypeScript and other implementations)
TEST_PSK = bytes.fromhex(
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

TEST_MESSAGES = {
    "empty": "",
    "single_char": "X",
    "whitespace": "   \t\n   ",
    "numbers": "1234567890",
    "punctuation": "!@#$%^&*()_+-=[]{}\\|;':\",./<>?",
    "newlines": "Line 1\nLine 2\nLine 3",
    "emoji_simple": "Hello 👋 World 🌍",
    "emoji_zwj": "Family: 👨\u200d👩\u200d👧\u200d👦",
    "chinese": "你好世界 - Hello World",
    "arabic": "مرحبا بالعالم",
    "japanese": "こんにちは世界 カタカナ 漢字",
    "korean": "안녕하세요 세계",
    "accents": "Café résumé naïve",
    "cyrillic": "Привет мир",
    "json": '{"key": "value", "num": 42}',
    "html": '<div class="test">Content</div>',
    "url": "https://example.com/path?q=test&lang=en",
    "code": 'func hello() { print("Hi") }',
    "long_text": "The quick brown fox jumps over the lazy dog. " * 11,
    "max_payload": "A" * 878,  # PSK max payload is 878 (vs 882 for v1.0)
}


def export_psk_envelopes(output_dir: str) -> None:
    """Generate and export PSK envelopes for all test messages."""
    alice_private, alice_public = derive_keys_from_seed(ALICE_SEED)
    bob_private, bob_public = derive_keys_from_seed(BOB_SEED)

    os.makedirs(output_dir, exist_ok=True)

    sorted_keys = sorted(TEST_MESSAGES.keys())

    for i, key in enumerate(sorted_keys):
        message = TEST_MESSAGES[key]
        # Derive the current PSK for this counter
        current_psk = derive_psk_at_counter(TEST_PSK, i)

        envelope = encrypt_psk_message(
            message,
            alice_private,
            alice_public,
            bob_public,
            current_psk,
            i,  # counter
        )
        encoded = encode_psk_envelope(envelope)
        with open(os.path.join(output_dir, f"{key}.hex"), "w") as f:
            f.write(encoded.hex())
        print(f"✓ {key} (counter={i})")

    # Write metadata
    metadata = {
        "pskHex": TEST_PSK.hex(),
        "counterStart": 0,
        "messageOrder": sorted_keys,
        "implementation": "python",
        "protocolVersion": "1.1",
    }
    with open(os.path.join(output_dir, "metadata.json"), "w") as f:
        json.dump(metadata, f, indent=2)

    print(f"Python: exported {len(TEST_MESSAGES)} PSK envelopes to {output_dir}")


def verify_psk_envelopes() -> None:
    """Verify PSK envelopes from all implementations."""
    bob_private, bob_public = derive_keys_from_seed(BOB_SEED)

    implementations = ["swift", "ts", "python", "rust", "kotlin"]
    total_passed = 0
    total_failed = 0

    sorted_keys = sorted(TEST_MESSAGES.keys())

    for impl in implementations:
        dir_path = f"test-envelopes-{impl}-psk"
        if not os.path.exists(dir_path):
            print(f"⚠ {impl}: PSK directory not found, skipping")
            continue

        # Read metadata to get the PSK
        psk = TEST_PSK
        meta_path = os.path.join(dir_path, "metadata.json")
        if os.path.exists(meta_path):
            with open(meta_path, "r") as f:
                meta = json.load(f)
            if "pskHex" in meta:
                psk = bytes.fromhex(meta["pskHex"])

        passed = 0
        failed = 0
        for key in sorted_keys:
            file_path = os.path.join(dir_path, f"{key}.hex")
            if not os.path.exists(file_path):
                continue
            try:
                with open(file_path, "r") as f:
                    hex_data = f.read().strip()
                envelope_bytes = bytes.fromhex(hex_data)
                if not is_psk_message(envelope_bytes):
                    failed += 1
                    print(f"  ✗ {impl}/{key}: not a PSK message")
                    continue
                envelope = decode_psk_envelope(envelope_bytes)

                # Derive the current PSK for this envelope's counter
                current_psk = derive_psk_at_counter(psk, envelope.ratchet_counter)

                result = decrypt_psk_message(
                    envelope,
                    bob_private,
                    bob_public,
                    current_psk,
                )
                expected = TEST_MESSAGES.get(key, "")
                if result == expected:
                    passed += 1
                else:
                    failed += 1
                    print(f"  ✗ {impl}/{key}: mismatch")
            except Exception as e:
                failed += 1
                print(f"  ✗ {impl}/{key}: {e}")

        print(f"{impl}: {passed}/{passed + failed} PSK envelopes verified")
        total_passed += passed
        total_failed += failed

    print(f"\nPSK Total: {total_passed}/{total_passed + total_failed} passed")
    if total_failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python_psk_cross_impl.py <export|verify> [output_dir]")
        sys.exit(1)

    command = sys.argv[1]
    if command == "export":
        output_dir = sys.argv[2] if len(sys.argv) > 2 else "test-envelopes-python-psk"
        export_psk_envelopes(output_dir)
    elif command == "verify":
        verify_psk_envelopes()
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)
