#!/usr/bin/env python3
"""RAWRXD_MODELGENIE_PRODUCTION_RUNTIME_001 - logit parity comparator.

Compares two float32 logit dumps (native vs reference) element-wise and reports
argmax agreement plus distributional error metrics. Standard library only.
"""
import argparse
import json
import math
import os
import struct
import sys


def read_f32(path):
    with open(path, "rb") as fh:
        data = fh.read()
    if len(data) % 4:
        raise ValueError("%s: size %d not a multiple of 4" % (path, len(data)))
    return struct.unpack("<%df" % (len(data) // 4), data)


def compare(native, ref, label=""):
    if len(native) != len(ref):
        return {"label": label, "error": "length mismatch %d vs %d" % (len(native), len(ref))}
    n = len(native)
    absdiff = [0.0] * n
    dot = 0.0
    nn = 0.0
    rn = 0.0
    max_abs = 0.0
    nan_native = 0
    for i in range(n):
        a = native[i]
        b = ref[i]
        if math.isnan(a) or math.isinf(a):
            nan_native += 1
        d = a - b
        absdiff[i] = abs(d)
        if abs(d) > max_abs:
            max_abs = abs(d)
        dot += a * b
        nn += a * a
        rn += b * b
    mean_abs = sum(absdiff) / n
    ordered = sorted(absdiff)
    median = ordered[n // 2] if n % 2 else 0.5 * (ordered[n // 2 - 1] + ordered[n // 2])
    p99 = ordered[min(n - 1, int(math.floor(0.99 * n)))]
    rmse = math.sqrt(sum(d * d for d in absdiff) / n)
    denom = math.sqrt(nn * rn)
    cosine = (dot / denom) if denom > 0 else 0.0

    def topk(vec, k):
        idx = sorted(range(len(vec)), key=lambda i: vec[i], reverse=True)[:k]
        return set(idx)

    top10 = topk(native, 10)
    top100 = topk(native, 100)
    rtop10 = topk(ref, 10)
    rtop100 = topk(ref, 100)

    return {
        "label": label,
        "count": n,
        "native_argmax": max(range(n), key=lambda i: native[i]),
        "ref_argmax": max(range(n), key=lambda i: ref[i]),
        "argmax_match": max(range(n), key=lambda i: native[i]) == max(range(n), key=lambda i: ref[i]),
        "nonfinite_native": nan_native,
        "max_abs_diff": max_abs,
        "mean_abs_diff": mean_abs,
        "median_abs_diff": median,
        "p99_abs_diff": p99,
        "rmse": rmse,
        "cosine_sim": cosine,
        "diff_at_ref_argmax": absdiff[max(range(n), key=lambda i: ref[i])],
        "top10_overlap": len(top10 & rtop10),
        "top100_overlap": len(top100 & rtop100),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--native", action="append", default=[])
    ap.add_argument("--ref", action="append", default=[])
    ap.add_argument("--label", action="append", default=[])
    ap.add_argument("--json-out")
    args = ap.parse_args()

    if not args.native or not args.ref or len(args.native) != len(args.ref):
        print("usage: compare_logits.py --native A --ref B [--native C --ref D]", file=sys.stderr)
        return 2

    labels = args.label if args.label else [os.path.basename(p) for p in args.native]

    results = []
    for i, (np_, rp) in enumerate(zip(args.native, args.ref)):
        results.append(compare(read_f32(np_), read_f32(rp), labels[i] if i < len(labels) else str(i)))

    for r in results:
        if "error" in r:
            print("%-14s ERROR %s" % (r["label"], r["error"]))
            continue
        print(
            "%-14s native_argmax=%-6d ref_argmax=%-6d match=%d cos=%.6f max|d|=%.6f rmse=%.6f mean|d|=%.6f top10=%d/10 top100=%d/100"
            % (
                r["label"],
                r["native_argmax"],
                r["ref_argmax"],
                1 if r["argmax_match"] else 0,
                r["cosine_sim"],
                r["max_abs_diff"],
                r["rmse"],
                r["mean_abs_diff"],
                r["top10_overlap"],
                r["top100_overlap"],
            )
        )

    if args.json_out:
        with open(args.json_out, "w") as fh:
            json.dump(results, fh, indent=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
