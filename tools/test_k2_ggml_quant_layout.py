"""GGML-layout cross-reference for independent scalar Q4_K and Q6_K decoders.

Reference loops independently transcribed from ggml-quants.c
dequantize_row_q4_K / dequantize_row_q6_K and get_scale_min_k4.
These are deterministic synthetic packed blocks, NOT a compiled ggml
library parity run or a real Kimi GPU parity receipt.
"""
import random
import struct
import unittest
from k2_q4k_scalar_oracle import unpack_block as q4_unpack
from k2_q6k_scalar_oracle import unpack_block as q6_unpack


def reference_q4(raw):
    d, dmin = struct.unpack_from("<ee", raw)
    scales, q = raw[4:16], raw[16:144]
    out = []
    is_ = 0
    for j in range(0, 256, 64):
        def get_scale_min(k):
            if k < 4:
                return (scales[k] & 63, scales[k + 4] & 63)
            return ((scales[k + 4] & 15) | ((scales[k - 4] >> 6) << 4),
                    (scales[k + 4] >> 4) | ((scales[k] >> 6) << 4))
        sc1, m1 = get_scale_min(is_)
        sc2, m2 = get_scale_min(is_ + 1)
        q_ = q[j // 2:j // 2 + 32]
        for x in q_:
            out.append((d * sc1) * (x & 15) - dmin * m1)
        for x in q_:
            out.append((d * sc2) * (x >> 4) - dmin * m2)
        is_ += 2
    return out


def reference_q6(raw):
    ql = raw[:128]
    qh = raw[128:192]
    scales = struct.unpack_from("<16b", raw, 192)
    d = struct.unpack_from("<e", raw, 208)[0]
    out = []
    for n in (0, 128):
        tile = [0.0] * 128
        for l in range(32):
            is_ = l // 16
            p = n // 2
            q = n // 4
            h = qh[q + l]
            z = (
                ((ql[p + l] & 15) | (((h >> 0) & 3) << 4)) - 32,
                ((ql[p + l + 32] & 15) | (((h >> 2) & 3) << 4)) - 32,
                ((ql[p + l] >> 4) | (((h >> 4) & 3) << 4)) - 32,
                ((ql[p + l + 32] >> 4) | (((h >> 6) & 3) << 4)) - 32,
            )
            for group in range(4):
                tile[l + 32 * group] = d * scales[(n // 16) + is_ + 2 * group] * z[group]
        out.extend(tile)
    return out


class QuantLayoutCrossReference(unittest.TestCase):
    def test_q4_directed_packed_groups(self):
        for seed in range(16):
            scales = bytes((37 * i + seed * 19) & 255 for i in range(12))
            nibbles = bytes((i * 91 + seed * 3) & 255 for i in range(128))
            block = struct.pack("<ee", 0.125, 0.375) + scales + nibbles
            with self.subTest(seed=seed):
                self.assertEqual(q4_unpack(block), reference_q4(block))

    def test_q6_directed_signed_scales(self):
        for seed in range(16):
            ql = bytes((i * 53 + seed * 7) & 255 for i in range(128))
            qh = bytes((i * 29 + seed * 13) & 255 for i in range(64))
            scales = struct.pack("<16b", *[(i * 17 + seed * 11) % 255 - 127
                                           for i in range(16)])
            block = ql + qh + scales + struct.pack("<e", 0.0625)
            with self.subTest(seed=seed):
                self.assertEqual(q6_unpack(block), reference_q6(block))

    def test_q4_seeded_randomized(self):
        rng = random.Random(20261027)
        for _ in range(24):
            scale = rng.choice([0.0, 0.5, 2.0, -0.25])
            minimum = rng.choice([0.0, 0.25, 1.0])
            raw = (struct.pack("<ee", scale, minimum) +
                   rng.randbytes(12 + 128))
            self.assertEqual(q4_unpack(raw), reference_q4(raw))

    def test_q6_seeded_randomized(self):
        rng = random.Random(20261028)
        for _ in range(24):
            raw = (rng.randbytes(128 + 64 + 16) +
                   struct.pack("<e", rng.choice([0.0, 0.25, -0.5, 1.0])))
            self.assertEqual(q6_unpack(raw), reference_q6(raw))


if __name__ == "__main__":
    unittest.main()
