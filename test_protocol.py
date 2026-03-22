from __future__ import annotations

import struct
import unittest

from miner.protocol import (
    POW_INPUT_SIZE,
    build_header_from_pow_input,
    build_pow_input,
    compact_size,
    header_meets_target,
)


class ProtocolTests(unittest.TestCase):
    def test_pow_input_byte_order_matches_zcash_header_layout(self) -> None:
        prev = bytes(range(32)).hex()
        merkle = bytes(range(32, 64)).hex()
        commitments = bytes(range(64, 96)).hex()

        template = {
            "version": 4,
            "previousblockhash": prev,
            "defaultroots": {
                "merkleroot": merkle,
                "blockcommitmentshash": commitments,
            },
            "curtime": 0x11223344,
            "bits": "1c01a11f",
        }

        pow_input = build_pow_input(template)
        self.assertEqual(len(pow_input), POW_INPUT_SIZE)

        expected = b"".join(
            [
                struct.pack("<i", 4),
                bytes.fromhex(prev)[::-1],
                bytes.fromhex(merkle)[::-1],
                bytes.fromhex(commitments)[::-1],
                struct.pack("<I", 0x11223344),
                bytes.fromhex("1c01a11f")[::-1],
            ]
        )
        self.assertEqual(pow_input, expected)

    def test_solution_size_1344_encodes_as_compact_size(self) -> None:
        self.assertEqual(compact_size(1344), b"\xfd\x40\x05")

    def test_header_builder_appends_nonce_then_solution_size_then_solution(self) -> None:
        pow_input = b"A" * POW_INPUT_SIZE
        nonce32 = b"B" * 32
        solution = b"C" * 1344
        header = build_header_from_pow_input(pow_input, nonce32, solution)
        self.assertEqual(header[:POW_INPUT_SIZE], pow_input)
        self.assertEqual(header[POW_INPUT_SIZE : POW_INPUT_SIZE + 32], nonce32)
        self.assertEqual(
            header[POW_INPUT_SIZE + 32 : POW_INPUT_SIZE + 35],
            b"\xfd\x40\x05",
        )
        self.assertEqual(header[POW_INPUT_SIZE + 35 :], solution)

    def test_target_check_accepts_zero_hash_only_for_zero_target(self) -> None:
        header = b""
        # sha256d(b"") is not zero, so a zero target must fail.
        self.assertFalse(header_meets_target(header, "00" * 32))
        # A max target must pass.
        self.assertTrue(header_meets_target(header, "ff" * 32))


if __name__ == "__main__":
    unittest.main()
