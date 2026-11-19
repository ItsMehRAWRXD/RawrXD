#!/usr/bin/env python3
"""Fail-closed full-logit comparison for LTT's count-prefixed FP32 capture.

Each record: uint64 little-endian vocabulary size, followed by that many
little-endian float32 logits. Reference must use the SAME format and token IDs.
"""
import argparse
import hashlib
import json
import math
import struct
import sys
from pathlib import Path

MAX_VOCAB = 2_000_000


def sha256(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def read_capture(path):
    with path.open("rb") as f:
        while True:
            header = f.read(8)
            if not header:
                return
            if len(header) != 8:
                raise ValueError("truncated count header")
            count, = struct.unpack("<Q", header)
            if not 1 <= count <= MAX_VOCAB:
                raise ValueError("invalid vocabulary size: %d" % count)
            payload = f.read(count * 4)
            if len(payload) != count * 4:
                raise ValueError("truncated FP32 payload")
            yield struct.unpack("<%df" % count, payload)


def topk(values, k=10):
    return sorted(range(len(values)), key=lambda i: (-values[i], i))[:k]


def compare(a, b):
    if len(a) != len(b):
        raise ValueError("vocabulary mismatch: %d != %d" % (len(a), len(b)))
    if not all(math.isfinite(x) for x in a + b):
        raise ValueError("nonfinite logits")
    errors = [abs(x - y) for x, y in zip(a, b)]
    ta, tb = topk(a), topk(b)
    return {
        "vocab": len(a),
        "max_abs": max(errors),
        "rms": math.sqrt(sum(e * e for e in errors) / len(errors)),
        "top1_match": ta[0] == tb[0],
        "top10_overlap": len(set(ta) & set(tb)),
        "first_max_error_index": errors.index(max(errors)),
        "ltt_top1": ta[0],
        "reference_top1": tb[0],
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--ltt", type=Path, required=True)
    p.add_argument("--reference", type=Path, required=True)
    p.add_argument("--receipt", type=Path, required=True)
    p.add_argument("--tokens", required=True, help="Comma-separated exact input token IDs")
    p.add_argument("--model-sha256", required=True, help="Exact shared model artifact SHA256")
    p.add_argument("--exe-sha256", required=True, help="LTT executable SHA256")
    p.add_argument("--reference-exe-sha256", required=True)
    p.add_argument("--max-abs", type=float, default=0.01)
    p.add_argument("--max-rms", type=float, default=0.001)
    args = p.parse_args()
    receipt = {"schema": 1, "status": "FAIL", "reason": "not evaluated"}
    try:
        token_ids = [int(x) for x in args.tokens.split(",")]
        if not token_ids or any(x < 0 or x > 0xffffffff for x in token_ids):
            raise ValueError("invalid token IDs")
        for name in ("model_sha256", "exe_sha256", "reference_exe_sha256"):
            value = getattr(args, name).lower()
            if len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
                raise ValueError("invalid " + name)
        if not math.isfinite(args.max_abs) or not math.isfinite(args.max_rms) or min(args.max_abs, args.max_rms) < 0:
            raise ValueError("invalid tolerance")
        a, b = list(read_capture(args.ltt)), list(read_capture(args.reference))
        if len(a) != len(b) or len(a) != len(token_ids):
            raise ValueError("token count mismatch: ltt=%d reference=%d expected=%d" % (len(a), len(b), len(token_ids)))
        results = [compare(x, y) for x, y in zip(a, b)]
        passing = all(x["top1_match"] and x["max_abs"] <= args.max_abs and x["rms"] <= args.max_rms for x in results)
        receipt = {
            "schema": 1,
            "status": "PASS" if passing else "FAIL",
            "token_ids": token_ids,
            "model_sha256": args.model_sha256.lower(),
            "ltt_exe_sha256": args.exe_sha256.lower(),
            "reference_exe_sha256": args.reference_exe_sha256.lower(),
            "ltt_capture_sha256": sha256(args.ltt),
            "reference_capture_sha256": sha256(args.reference),
            "tolerances": {"max_abs": args.max_abs, "max_rms": args.max_rms},
            "positions": results,
        }
    except (OSError, ValueError, OverflowError, struct.error) as exc:
        receipt["reason"] = str(exc)
    args.receipt.parent.mkdir(parents=True, exist_ok=True)
    args.receipt.write_text(json.dumps(receipt, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    print("LTT_PARITY_" + receipt["status"], args.receipt)
    return 0 if receipt["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
