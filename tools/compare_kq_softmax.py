#!/usr/bin/env python3
"""Compare native Attention_Weights captures against the reference kq_soft_max
(attention weights / softmax output) from the 64-position reference (ref_64).

This directly tests the attention score scale factor: the softmax output changes
with the scale, so mscale^2 (which the reference was captured with) should match
the reference exactly, while plain 1/sqrt(192) should not.

Usage: compare_kq_softmax.py <native_dir> <step> <layer>
"""
import os
import struct
import sys

REF = r"F:\rawrxd\evidence\RAWRXD_REFERENCE_REPRODUCIBILITY_001\ref_64"


def read_ref_kqsoftmax(path):
    """Read a RAWH-formatted reference kq_soft_max file.
    Layout: 'RAWH' magic(4) + 4x i64 dims(32) + 32 bytes extra + float32 data."""
    raw = open(path, "rb").read()
    assert raw[:4] == b"RAWH", "not RAWH"
    ne = struct.unpack_from("<4q", raw, 4)  # ne[0]=256(pos), ne[1]=1, ne[2]=16(heads)
    n_floats = (len(raw) - 68) // 4
    vals = struct.unpack_from("<%df" % n_floats, raw, 68)
    return list(vals), ne


def read_native_scores(path):
    """Read a native DifferentialRecorder capture file (rec_*.bin).
    Layout: op_id(u32) + layer(u32) + position(u64) + ndim(u32) + dims[i64*ndim] +
            count(u64) + float32 data[].
    """
    raw = open(path, "rb").read()
    off = 0
    (op_id, layer) = struct.unpack_from("<II", raw, off)
    off += 8
    (position,) = struct.unpack_from("<Q", raw, off)
    off += 8
    (ndim,) = struct.unpack_from("<I", raw, off)
    off += 4
    dims = []
    for _ in range(ndim):
        dims.append(struct.unpack_from("<q", raw, off)[0])
        off += 8
    (count,) = struct.unpack_from("<Q", raw, off)
    off += 8
    vals = struct.unpack_from("<%df" % count, raw, off)
    return list(vals), dims, position, op_id


def met(a, b, max_positions=None):
    """Compare two arrays. If max_positions is set, only compare first N non-zero
    entries (extracting the relevant slice from the reference's padded layout)."""
    if max_positions:
        n = min(len(a), max_positions, len(b))
    else:
        n = min(len(a), len(b))
    if n == 0:
        return None
    dot = 0.0
    na = 0.0
    nb = 0.0
    se = 0.0
    mx = 0.0
    for i in range(n):
        x, y = a[i], b[i]
        dot += x * y
        na += x * x
        nb += y * y
        se += (x - y) ** 2
        mx = max(mx, abs(x - y))
    den = (na ** 0.5) * (nb ** 0.5)
    cos = dot / den if den > 0 else 0.0
    rmse = (se / n) ** 0.5
    amax = max(range(n), key=lambda i: a[i])
    bmax = max(range(n), key=lambda i: b[i])
    return {"n": n, "cos": cos, "rmse": rmse, "max": mx,
            "argmax_match": amax == bmax, "native_argmax": amax, "ref_argmax": bmax}


def main():
    if len(sys.argv) < 4:
        print("Usage: compare_kq_softmax.py <native_dir> <step> <layer>")
        print("  step: 0-64 (position index)")
        print("  layer: 0-26")
        sys.exit(1)

    native_dir = sys.argv[1]
    step = int(sys.argv[2])
    layer = int(sys.argv[3])

    # Reference step is stepNN -> step index in ref_64
    # Native "position" field should match: ref step00 = pos0, step01 = pos1, etc.
    # At step N (position N), there are N+1 positions in context (0..N),
    # and 16 heads, so native Attention_Weights has 16*(N+1) floats.

    ref_fn = "probe_step%02d_kq_soft_max_l%02d.bin" % (step, layer)
    ref_path = os.path.join(REF, ref_fn)
    if not os.path.isfile(ref_path):
        print("REF MISSING: %s" % ref_path)
        sys.exit(1)

    ref_vals, ref_ne = read_ref_kqsoftmax(ref_path)
    ref_npos = ref_ne[0]  # 256 (padded context)
    ref_nheads = ref_ne[2]  # 16

    # Extract the first (step+1) positions per head from the reference
    n_active = step + 1
    ref_trimmed = []
    for h in range(ref_nheads):
        for p in range(n_active):
            ref_trimmed.append(ref_vals[h * ref_npos + p])

    # Find native Attention_Weights file
    # Name pattern: rec_*_op*_Attention_Weights_l{layer}_p{step}_softmax.bin
    nat_files = []
    for fn in os.listdir(native_dir):
        if "Attention_Weights" in fn and "softmax" in fn:
            # Parse: rec_{op}_op{op}_{...}_l{layer}_p{step}_softmax.bin
            parts = fn.replace(".bin", "").split("_")
            try:
                # Find lNN and pNN in the parts
                lidx = None
                pidx = None
                for i, part in enumerate(parts):
                    if part.startswith("l"):
                        lidx = int(part[1:])
                    if part.startswith("p"):
                        pidx = int(part[1:])
                if lidx == layer and pidx == step:
                    nat_files.append(fn)
            except (ValueError, IndexError):
                continue

    if not nat_files:
        print("NATIVE MISSING: no Attention_Weights for step=%d layer=%d in %s" %
              (step, layer, native_dir))
        sys.exit(1)

    for fn in sorted(nat_files):
        nat_path = os.path.join(native_dir, fn)
        nat_vals, nat_dims, nat_pos, nat_op = read_native_scores(nat_path)

        expected_n = ref_nheads * n_active
        if len(nat_vals) != expected_n:
            print("  %s: native has %d floats, ref has %d (expected %d)" %
                  (fn, len(nat_vals), len(ref_trimmed), expected_n))
            continue

        m = met(nat_vals, ref_trimmed)
        if m:
            print("step=%d layer=%d: cos=%.8f  max_diff=%.2e  rmse=%.2e  argmax nat/ref=%d/%d  %s" %
                  (step, layer, m["cos"], m["max"], m["rmse"], m["native_argmax"],
                   m["ref_argmax"], "MATCH" if m["argmax_match"] else "MISMATCH"))
            # Also check ratio
            import math
            na = math.sqrt(sum(x*x for x in nat_vals))
            nb = math.sqrt(sum(x*x for x in ref_trimmed))
            print("  scale_ratio (native/ref norm) = %.6f" % (na/nb if nb > 0 else 0))


if __name__ == "__main__":
    main()
