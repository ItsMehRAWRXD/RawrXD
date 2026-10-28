#!/usr/bin/env python3
"""Independent Q6_K x Q8_K down-GEMV oracle matching deep2_qgemv.comp type==14.

Contract (shader-aligned, not FP32 dequant*x):
  - Columns processed in 256-wide super-blocks (QK_K).
  - Each super-block: find signed max-abs activation, q8InvScale=-127/maxValue,
    quantize with ggml nearest-int magic 12582912, clamp [-127,127].
  - Packed Q6_K block is exactly 210 bytes (ql128 + qh64 + scales16 + d:f16).
  - Dot: q8D * q8 * d * scale * (q-32) accumulated with math.fsum.

Does not import Deep2 C++/Vulkan kernels. Diagnostic only; certified=false.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import struct
from pathlib import Path

try:
    import numpy as np
except ImportError:  # pragma: no cover
    np = None  # type: ignore

QK_K = 256
BLOCK_BYTES = 210
MAGIC = 12582912.0  # 1.5 * 2^23 — same as deep2_qgemv.comp / ggml


def nearest_int_q8(fval: float) -> int:
    """GLSL: int(floatBitsToInt(f + MAGIC) & 0x007fffff) - 0x00400000."""
    bits = struct.unpack("<I", struct.pack("<f", float(fval) + MAGIC))[0]
    return (bits & 0x007FFFFF) - 0x00400000


def quantize_q8k_block(x_block: list[float]) -> tuple[list[int], float]:
    """Per-256 act quant; returns (q8[256], q8D)."""
    if len(x_block) != QK_K:
        raise ValueError("Q8_K block requires 256 activations")
    amax = 0.0
    max_value = 0.0
    for value in x_block:
        if not math.isfinite(value):
            raise ValueError("nonfinite activation")
        av = abs(value)
        if av > amax:
            amax = av
            max_value = value
    if amax == 0.0:
        return [0] * QK_K, 0.0
    inv = -127.0 / max_value
    q8d = 1.0 / inv
    out = []
    for value in x_block:
        q = nearest_int_q8(inv * value)
        if q < -127:
            q = -127
        elif q > 127:
            q = 127
        out.append(q)
    return out, q8d


def unpack_q6k_qs_scales_d(block: bytes) -> tuple[list[int], list[int], float]:
    """Return qs[256] (already q-32), int8 scales[16], and d (f16)."""
    if len(block) != BLOCK_BYTES:
        raise ValueError("Q6_K block requires exactly 210 bytes")
    ql = block[:128]
    qh = block[128:192]
    scales = list(struct.unpack_from("<16b", block, 192))
    d = struct.unpack_from("<e", block, 208)[0]
    if not math.isfinite(d):
        raise ValueError("nonfinite Q6_K scale")
    qs = [0] * QK_K
    for half in range(2):
        o = half * 64
        out_base = half * 128
        for l in range(32):
            h = qh[half * 32 + l]
            low0 = ql[o + l]
            low1 = ql[o + l + 32]
            quantized = (
                (low0 & 15) | ((h & 3) << 4),
                (low1 & 15) | (((h >> 2) & 3) << 4),
                (low0 >> 4) | (((h >> 4) & 3) << 4),
                (low1 >> 4) | (((h >> 6) & 3) << 4),
            )
            for group, q in enumerate(quantized):
                qs[out_base + group * 32 + l] = int(q) - 32
    return qs, scales, float(d)


def _scale_index_table() -> list[int]:
    scale_index = [0] * QK_K
    for half in range(2):
        out_base = half * 128
        for group in range(4):
            for l in range(32):
                idx = out_base + group * 32 + l
                scale_index[idx] = half * 8 + group * 2 + (l // 16)
    return scale_index


def _unpack_all_blocks_np(blob: bytes, n_blocks: int, scale_index):
    """Vectorized unpack of contiguous 210-byte Q6_K blocks -> qs, scale_map, d."""
    assert np is not None
    raw = np.frombuffer(blob, dtype=np.uint8)
    if raw.size != n_blocks * BLOCK_BYTES:
        raise ValueError("weight size mismatch for numpy unpack")
    blocks = raw.reshape(n_blocks, BLOCK_BYTES)
    ql = blocks[:, 0:128]
    qh = blocks[:, 128:192]
    scales = blocks[:, 192:208].view(np.int8)
    d = blocks[:, 208:210].copy().view(np.float16).reshape(n_blocks).astype(np.float64)
    if not np.all(np.isfinite(d)):
        raise ValueError("nonfinite Q6_K scale")

    qs = np.empty((n_blocks, QK_K), dtype=np.int16)
    for half in range(2):
        o = half * 64
        out_base = half * 128
        h = qh[:, half * 32 : half * 32 + 32]
        low0 = ql[:, o : o + 32]
        low1 = ql[:, o + 32 : o + 64]
        q0 = (low0 & 15) | ((h & 3) << 4)
        q1 = (low1 & 15) | (((h >> 2) & 3) << 4)
        q2 = (low0 >> 4) | (((h >> 4) & 3) << 4)
        q3 = (low1 >> 4) | (((h >> 6) & 3) << 4)
        qs[:, out_base + 0:out_base + 32] = q0.astype(np.int16) - 32
        qs[:, out_base + 32:out_base + 64] = q1.astype(np.int16) - 32
        qs[:, out_base + 64:out_base + 96] = q2.astype(np.int16) - 32
        qs[:, out_base + 96:out_base + 128] = q3.astype(np.int16) - 32

    scale_map = scales[:, scale_index].astype(np.float64)
    return qs.astype(np.float64), scale_map, d


def gemv_q6k_q8k(blob: bytes, x: list[float], rows: int, columns: int) -> list[float]:
    if rows <= 0 or columns <= 0 or columns % QK_K:
        raise ValueError("rows>0 and columns multiple of 256 required")
    if len(x) != columns or not all(math.isfinite(v) for v in x):
        raise ValueError("input length mismatch or nonfinite input")
    needed = rows * (columns // QK_K) * BLOCK_BYTES
    if len(blob) != needed:
        raise ValueError(f"weight size mismatch: got {len(blob)}, expected {needed}")

    blocks_per_row = columns // QK_K
    scale_index = _scale_index_table()

    # Pre-quantize each activation super-block once (shared across rows).
    act_blocks = []
    for start in range(0, columns, QK_K):
        q8, q8d = quantize_q8k_block(x[start : start + QK_K])
        act_blocks.append((q8, q8d))

    if np is not None:
        q8_mat = np.array([b[0] for b in act_blocks], dtype=np.float64)
        q8d_vec = np.array([b[1] for b in act_blocks], dtype=np.float64)
        n_blocks = rows * blocks_per_row
        qs, scale_map, d = _unpack_all_blocks_np(blob, n_blocks, scale_index)
        qs = qs.reshape(rows, blocks_per_row, QK_K)
        scale_map = scale_map.reshape(rows, blocks_per_row, QK_K)
        d = d.reshape(rows, blocks_per_row)
        # Shader: sum q8D * q8 * d * scale * qs — no 14M Python list.
        contrib = (
            q8d_vec[None, :, None]
            * q8_mat[None, :, :]
            * d[:, :, None]
            * scale_map
            * qs
        )
        out_arr = contrib.sum(axis=(1, 2))
        if not np.all(np.isfinite(out_arr)):
            raise ValueError("nonfinite oracle output")
        return [float(v) for v in out_arr]

    out: list[float] = []
    offset = 0
    for _ in range(rows):
        acc = 0.0
        for bidx in range(blocks_per_row):
            block = blob[offset : offset + BLOCK_BYTES]
            offset += BLOCK_BYTES
            qs, scales, d = unpack_q6k_qs_scales_d(block)
            q8, q8d = act_blocks[bidx]
            for idx in range(QK_K):
                acc += q8d * q8[idx] * d * scales[scale_index[idx]] * qs[idx]
        if not math.isfinite(acc):
            raise ValueError("nonfinite oracle output")
        out.append(float(acc))
    return out


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--weights", required=True)
    p.add_argument("--input", required=True, help="Post-SwiGLU / ArenaFFNAct floats")
    p.add_argument("--rows", required=True, type=int)
    p.add_argument("--columns", required=True, type=int)
    p.add_argument("--output", required=True)
    p.add_argument("--receipt", required=True)
    a = p.parse_args(argv)
    try:
        weight_bytes = Path(a.weights).read_bytes()
        input_bytes = Path(a.input).read_bytes()
        x = []
        for line in input_bytes.decode("utf-8").splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                x.append(float(line))
        y = gemv_q6k_q8k(weight_bytes, x, a.rows, a.columns)
        Path(a.output).write_text("".join(f"{v:.17g}\n" for v in y), encoding="utf-8")
        receipt = {
            "schema": "DEEP2_KIMI_Q6K_Q8K_ORACLE_001/v1",
            "status": "PASS_DIAGNOSTIC",
            "certified": False,
            "contract": "Q6_K_x_Q8_K",
            "shader_alignment": "deep2_qgemv.comp type==14",
            "rows": a.rows,
            "columns": a.columns,
            "ggml_type": 14,
            "qk_k": QK_K,
            "block_bytes": BLOCK_BYTES,
            "weight_sha256": hashlib.sha256(weight_bytes).hexdigest(),
            "input_sha256": hashlib.sha256(input_bytes).hexdigest(),
            "output_sha256": hashlib.sha256(Path(a.output).read_bytes()).hexdigest(),
            "method": "Python Q8_K act quant (MAGIC=12582912) + Q6_K packed (numpy GEMV if available)",
            "PROMOTE": 0,
            "TIP_CLIMB": "HOLD",
        }
        code = 0
    except (ValueError, OSError, UnicodeError, OverflowError, struct.error) as exc:
        receipt = {
            "schema": "DEEP2_KIMI_Q6K_Q8K_ORACLE_001/v1",
            "status": "ERROR",
            "certified": False,
            "error": str(exc),
            "PROMOTE": 0,
        }
        code = 3
    Path(a.receipt).write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(receipt["status"])
    return code


if __name__ == "__main__":
    raise SystemExit(main())
