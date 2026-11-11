#!/usr/bin/env python3
"""Independent ggml Q4_K dequantizer - RAWRXD_MODELGENIE_PRODUCTION_RUNTIME_001

Reads a named tensor straight out of the GGUF file and applies the ggml
reference algorithm (ggml.c dequantize_row_q4_K) so the native executor's
dequantization can be diffed element-by-element.

Usage: ggml_q4k_ref.py <gguf> <tensor_name> <out_f32>
"""
import struct
import sys

GGUF_MAGIC = 0x46554747
TYPE_SIZES = {0: 1, 1: 1, 2: 2, 3: 2, 4: 4, 5: 4, 6: 4, 7: 1, 8: 0, 9: 0, 10: 8, 11: 8, 12: 8}


def fp16(b):
    return struct.unpack("<e", b)[0]


def read_string(d, off):
    (n,) = struct.unpack_from("<Q", d, off)
    off += 8
    return d[off:off + n].decode("utf-8", "replace"), off + n


def skip_value(d, off, t):
    if t == 8:
        _, off = read_string(d, off)
        return off
    if t == 9:
        (et,) = struct.unpack_from("<I", d, off)
        off += 4
        (cnt,) = struct.unpack_from("<Q", d, off)
        off += 8
        for _ in range(cnt):
            off = skip_value(d, off, et)
        return off
    if t not in TYPE_SIZES:
        raise ValueError("unknown GGUF type %d" % t)
    return off + TYPE_SIZES[t]


def parse_header(d):
    magic, version = struct.unpack_from("<II", d, 0)
    if magic != GGUF_MAGIC:
        raise ValueError("not a GGUF file")
    off = 8
    (n_tensors,) = struct.unpack_from("<Q", d, off)
    off += 8
    (n_kv,) = struct.unpack_from("<Q", d, off)
    off += 8
    for _ in range(n_kv):
        _, off = read_string(d, off)
        (t,) = struct.unpack_from("<I", d, off)
        off += 4
        off = skip_value(d, off, t)
    tensors = {}
    for _ in range(n_tensors):
        name, off = read_string(d, off)
        (nd,) = struct.unpack_from("<I", d, off)
        off += 4
        dims = list(struct.unpack_from("<%dQ" % nd, d, off))
        off += 8 * nd
        (offset,) = struct.unpack_from("<Q", d, off)
        off += 8
        (tid,) = struct.unpack_from("<I", d, off)
        off += 4
        tensors[name] = {"dims": dims, "offset": offset, "type": tid}
    return tensors, off


# ggml.c: static inline void get_scale_min_k4
def get_scale_min_k4(j, q):
    if j < 4:
        return q[j] & 63, q[j + 4] & 63
    d = (q[j + 4] & 0x0F) | ((q[j - 4] >> 6) << 4)
    m = (q[j + 4] >> 4) | ((q[j + 0] >> 6) << 4)
    return d, m


def dequantize_q4_k(blocks):
    """ggml.c dequantize_row_q4_K, verbatim."""
    y = []
    for x in blocks:
        d, dmin = x[0], x[1]
        scales, qs = x[2], x[3]
        q = qs
        is_k = 0
        for j in range(0, 256, 64):
            sc, m = get_scale_min_k4(is_k + 0, scales)
            d1, m1 = d * sc, dmin * m
            sc, m = get_scale_min_k4(is_k + 1, scales)
            d2, m2 = d * sc, dmin * m
            for l in range(32):
                y.append(d1 * (q[l] & 0xF) - m1)
            for l in range(32):
                y.append(d2 * (q[l] >> 4) - m2)
            q = q[32:]
            is_k += 2
    return y


def main():
    gguf, name, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
    d = open(gguf, "rb").read()
    tensors, dir_end = parse_header(d)
    if name not in tensors:
        raise SystemExit("tensor not found: %s" % name)
    t = tensors[name]
    if t["type"] != 12:
        raise SystemExit("tensor %s is not Q4_K (type=%d)" % (name, t["type"]))

    n = 1
    for v in t["dims"]:
        n *= v
    nblocks = n // 256

    alignment = 32
    data_start = dir_end + ((alignment - (dir_end % alignment)) % alignment)
    base = data_start + t["offset"]

    blocks = []
    for b in range(nblocks):
        o = base + b * 144
        dd = fp16(d[o:o + 2])
        dm = fp16(d[o + 2:o + 4])
        scales = d[o + 4:o + 16]
        qs = d[o + 16:o + 144]
        blocks.append((dd, dm, scales, qs))

    y = dequantize_q4_k(blocks)
    assert len(y) == n, (len(y), n)
    open(out_path, "wb").write(struct.pack("<%df" % len(y), *y))
    print("%s: dims=%s offset=%d type=%d blocks=%d elements=%d -> %s"
          % (name, t["dims"], base, t["type"], nblocks, len(y), out_path))


if __name__ == "__main__":
    main()
