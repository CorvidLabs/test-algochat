#!/usr/bin/env python3
"""Cross-implementation envelope generation and verification for AlgoChat."""

import os
import sys
from algochat import (
    derive_keys_from_seed,
    encrypt_message,
    encode_envelope,
    decrypt_message,
    decode_envelope,
    is_chat_message,
)

ALICE_SEED = bytes.fromhex(
    "0000000000000000000000000000000000000000000000000000000000000001"
)
BOB_SEED = bytes.fromhex(
    "0000000000000000000000000000000000000000000000000000000000000002"
)

TEST_MESSAGES = {
    "empty": "",
    "single_char": "X",
    "whitespace": "   \t\n   ",
    "numbers": "1234567890",
    "punctuation": "!@#$%^&*()_+-=[]{}\\|;':\",./<>?",
    "newlines": "Line 1\nLine 2\nLine 3",
    "emoji_simple": "Hello 👋 World 🌍",
    "emoji_zwj": "Family: 👨‍👩‍👧‍👦",
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
    "max_payload": "A" * 882,
}


def export_envelopes(output_dir: str) -> None:
    """Generate and export envelopes for all test messages."""
    alice_private, alice_public = derive_keys_from_seed(ALICE_SEED)
    bob_private, bob_public = derive_keys_from_seed(BOB_SEED)

    os.makedirs(output_dir, exist_ok=True)

    for key, message in TEST_MESSAGES.items():
        envelope = encrypt_message(message, alice_private, alice_public, bob_public)
        encoded = encode_envelope(envelope)
        with open(os.path.join(output_dir, f"{key}.hex"), "w") as f:
            f.write(encoded.hex())
        print(f"✓ {key}")

    print(f"Python: exported {len(TEST_MESSAGES)} envelopes to {output_dir}")


def verify_envelopes() -> None:
    """Verify envelopes from all implementations."""
    bob_private, bob_public = derive_keys_from_seed(BOB_SEED)

    implementations = ["swift", "ts", "python", "rust", "kotlin"]
    total_passed = 0
    total_failed = 0

    for impl in implementations:
        dir_path = f"test-envelopes-{impl}"
        if not os.path.exists(dir_path):
            print(f"⚠ {impl}: directory not found, skipping")
            continue

        passed = 0
        failed = 0
        for key, expected in TEST_MESSAGES.items():
            file_path = os.path.join(dir_path, f"{key}.hex")
            if not os.path.exists(file_path):
                continue
            try:
                with open(file_path, "r") as f:
                    hex_data = f.read().strip()
                envelope_bytes = bytes.fromhex(hex_data)
                if not is_chat_message(envelope_bytes):
                    failed += 1
                    continue
                envelope = decode_envelope(envelope_bytes)
                result = decrypt_message(envelope, bob_private, bob_public)
                if result and result.text == expected:
                    passed += 1
                else:
                    failed += 1
                    print(f"  ✗ {impl}/{key}: mismatch")
            except Exception as e:
                failed += 1
                print(f"  ✗ {impl}/{key}: {e}")

        print(f"{impl}: {passed}/{passed + failed} passed")
        total_passed += passed
        total_failed += failed

    print(f"\nTotal: {total_passed}/{total_passed + total_failed} passed")
    if total_failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python_cross_impl.py <export|verify> [output_dir]")
        sys.exit(1)

    command = sys.argv[1]
    if command == "export":
        output_dir = sys.argv[2] if len(sys.argv) > 2 else "test-envelopes-python"
        export_envelopes(output_dir)
    elif command == "verify":
        verify_envelopes()
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)
