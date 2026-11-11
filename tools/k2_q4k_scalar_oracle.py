#!/usr/bin/env python3
"""Independent scalar GGML Q4_K reference for expert gate/up GEMV.

QK_K=256, block=144 bytes: d/f16, dmin/f16, scales[12], qs[128].
No optimized Deep2/ggml kernel is invoked. Float64 accumulation is used.
"""
import argparse
import hashlib
import json
import math
from pathlib import Path
import struct

QK_K = 256
BLOCK_BYTES = 144


def scale_min(scales, group):
    if not 0 <= group < 8 or len(scales) != 12:
        raise ValueError("invalid Q4_K scale group")
    if group < 4:
        return scales[group] & 63, scales[group + 4] & 63
    return ((scales[group + 4] & 15) | ((scales[group - 4] >> 6) << 4),
            (scales[group + 4] >> 4) | ((scales[group] >> 6) << 4))


def unpack_block(blob):
    if len(blob) != BLOCK_BYTES:
        raise ValueError("Q4_K block requires exactly 144 bytes")
    d, dmin = struct.unpack_from("<ee", blob)
    if not math.isfinite(d) or not math.isfinite(dmin):
        raise ValueError("nonfinite Q4_K FP16 scale")
    scales = blob[4:16]
    qs = blob[16:]
    values = []
    for group in range(4):
        lower_s, lower_m = scale_min(scales, 2 * group)
        upper_s, upper_m = scale_min(scales, 2 * group + 1)
        block_q = qs[group * 32:group * 32 + 32]
        values.extend(d * lower_s * (b & 15) - dmin * lower_m for b in block_q)
        values.extend(d * upper_s * (b >> 4) - dmin * upper_m for b in block_q)
    return values


def gemv(weights, x, rows, columns):
    if rows <= 0 or columns <= 0 or columns % QK_K:
        raise ValueError("Q4_K requires rows>0, columns positive multiple of 256")
    if len(x) != columns or not all(math.isfinite(v) for v in x):
        raise ValueError("input size mismatch or nonfinite activation")
    expected = rows * (columns // QK_K) * BLOCK_BYTES
    if len(weights) != expected:
        raise ValueError(f"Q4_K packed weight bytes {len(weights)} != {expected}")
    output = []
    offset = 0
    for _ in range(rows):
        products = []
        for col in range(0, columns, QK_K):
            unpacked = unpack_block(weights[offset:offset + BLOCK_BYTES])
            products.extend(x[col + i] * v for i, v in enumerate(unpacked))
            offset += BLOCK_BYTES
        value = math.fsum(products)
        if not math.isfinite(value):
            raise ValueError("nonfinite scalar Q4_K GEMV output")
        output.append(value)
    return output


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--weights", type=Path, required=True)
    p.add_argument("--input", type=Path, required=True)
    p.add_argument("--rows", type=int, required=True)
    p.add_argument("--columns", type=int, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--receipt", type=Path, required=True)
    a = p.parse_args(argv)
    try:
        packed = a.weights.read_bytes()
        input_bytes = a.input.read_bytes()
        x = [float(line.split("#", 1)[0].strip()) for line in
             input_bytes.decode("utf-8").splitlines()
             if line.split("#", 1)[0].strip()]
        output = gemv(packed, x, a.rows, a.columns)
        output_bytes = "".join(f"{v:.17g}\n" for v in output).encode("utf-8")
        a.output.write_bytes(output_bytes)
        receipt = {
            "schema": "DEEP2_KIMI_Q4K_SCALAR_ORACLE_001/v1",
            "status": "PASS_DIAGNOSTIC", "certified": False,
            "ggml_type": 12, "rows": a.rows, "columns": a.columns,
            "input_sha256": hashlib.sha256(input_bytes).hexdigest(),
            "weights_sha256": hashlib.sha256(packed).hexdigest(),
            "output_sha256": hashlib.sha256(output_bytes).hexdigest(),
            "note": "Independent scalar Q4_K arithmetic; no real-model or GPU certification",
        }
        rc = 0
    except (ValueError, OSError, UnicodeError, OverflowError, struct.error) as exc:
        receipt = {"schema": "DEEP2_KIMI_Q4K_SCALAR_ORACLE_001/v1",
                   "status": "ERROR", "certified": False, "error": str(exc)}
        rc = 3
    a.receipt.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n",
                         encoding="utf-8")
    print(receipt["status"])
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
