from __future__ import annotations

import unittest

from miner.protocol import (
    POW_INPUT_SIZE,
    POW_SOLUTION_SIZE,
    bits_hex_to_le_bytes,
    build_header_from_pow_input,
    compact_size,
    header_meets_target,
    reverse32_hex,
)


class ProtocolTests(unittest.TestCase):
    def test_reverse32_hex_roundtrip_shape(self) -> None:
        src = '11' * 32
        self.assertEqual(reverse32_hex(src), bytes.fromhex(src)[::-1])

    def test_bits_hex_to_le_bytes(self) -> None:
        self.assertEqual(bits_hex_to_le_bytes('1d00ffff'), bytes.fromhex('ffff001d'))

    def test_compact_size_for_1344(self) -> None:
        self.assertEqual(compact_size(1344), bytes([0xFD, 0x40, 0x05]))

    def test_header_meets_target_with_zero_hash(self) -> None:
        header = b''
        target_hex = 'ff' * 32
        self.assertTrue(header_meets_target(header, target_hex))

    def test_header_layout_matches_expected_fixed_size(self) -> None:
        pow_input = bytes(POW_INPUT_SIZE)
        nonce = bytes(32)
        solution = bytes(POW_SOLUTION_SIZE)
        header = build_header_from_pow_input(pow_input, nonce, solution)
        self.assertEqual(len(header), POW_INPUT_SIZE + 32 + 3 + POW_SOLUTION_SIZE)
        self.assertEqual(header[:POW_INPUT_SIZE], pow_input)
        self.assertEqual(header[POW_INPUT_SIZE:POW_INPUT_SIZE + 32], nonce)
        self.assertEqual(header[POW_INPUT_SIZE + 32:POW_INPUT_SIZE + 35], bytes([0xFD, 0x40, 0x05]))


if __name__ == '__main__':
    unittest.main()
