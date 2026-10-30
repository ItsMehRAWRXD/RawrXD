#!/usr/bin/env python3
"""Independent, deliberately scalar GGML Q6_K down-GEMV oracle.

Packed bytes are one expert's Q6_K matrix in row-major blocks, with columns
divisible by 256. No Deep2 quant kernel or Vulkan implementation is reused.
The input vector is the post-SwiGLU activation passed to down-GEMV.
"""
import argparse
import hashlib
import json
import math
import struct
from pathlib import Path

QK_K = 256
BLOCK_BYTES = 210  # ql[128], qh[64], scales[16], d:f16


def unpack_block(block):
    if len(block) != BLOCK_BYTES:
        raise ValueError("Q6_K block requires exactly 210 bytes")
    ql = block[:128]
    qh = block[128:192]
    scales = struct.unpack_from("<16b", block, 192)
    d = struct.unpack_from("<e", block, 208)[0]
    if not math.isfinite(d):
        raise ValueError("nonfinite Q6_K scale")
    values = [0.0] * QK_K
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
                scale_index = half * 8 + group * 2 + l // 16
                values[out_base + group * 32 + l] = d * scales[scale_index] * (q - 32)
    return values


def gemv(blob, x, rows, columns):
    if rows <= 0 or columns <= 0 or columns % QK_K:
        raise ValueError("rows must be positive and columns a positive multiple of 256")
    if len(x) != columns or not all(math.isfinite(v) for v in x):
        raise ValueError("input length mismatch or nonfinite input")
    needed = rows * (columns // QK_K) * BLOCK_BYTES
    if len(blob) != needed:
        raise ValueError(f"weight size mismatch: got {len(blob)}, expected {needed}")
    out = []
    offset = 0
    # Avoid building a 14M-element products list: fsum per 256-block, then fsum of
    # the few block partials (secondary FP32 telemetry only).
    for _ in range(rows):
        partials = []
        for start in range(0, columns, QK_K):
            decoded = unpack_block(blob[offset:offset + BLOCK_BYTES])
            offset += BLOCK_BYTES
            partials.append(
                math.fsum(decoded[i] * x[start + i] for i in range(QK_K))
            )
        result = math.fsum(partials)
        if not math.isfinite(result):
            raise ValueError("nonfinite oracle output")
        out.append(result)
    return out


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--weights", required=True, help="Raw packed Q6_K expert down matrix")
    p.add_argument("--input", required=True, help="Post-SwiGLU activation, one float per line")
    p.add_argument("--rows", required=True, type=int)
    p.add_argument("--columns", required=True, type=int)
    p.add_argument("--output", required=True, help="Oracle output, one float per line")
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
        out = gemv(weight_bytes, x, a.rows, a.columns)
        Path(a.output).write_text("".join(f"{v:.17g}\n" for v in out), encoding="utf-8")
        receipt = {
            "schema": "DEEP2_KIMI_Q6K_SCALAR_ORACLE_001/v1",
            "status": "PASS_DIAGNOSTIC",
            "certified": False,
            "rows": a.rows, "columns": a.columns,
            "ggml_type": 14, "qk_k": QK_K, "block_bytes": BLOCK_BYTES,
            "weight_sha256": hashlib.sha256(weight_bytes).hexdigest(),
            "input_sha256": hashlib.sha256(input_bytes).hexdigest(),
            "output_sha256": hashlib.sha256(Path(a.output).read_bytes()).hexdigest(),
            "method": "Python struct f16 + scalar unpack + math.fsum; no optimized GEMV",
        }
        code = 0
    except (ValueError, OSError, UnicodeError, OverflowError, struct.error) as exc:
        receipt = {"schema": "DEEP2_KIMI_Q6K_SCALAR_ORACLE_001/v1",
                   "status": "ERROR", "certified": False, "error": str(exc)}
        code = 3
    Path(a.receipt).write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n",
                               encoding="utf-8")
    print(receipt["status"])
    return code


if __name__ == "__main__":
    raise SystemExit(main())
