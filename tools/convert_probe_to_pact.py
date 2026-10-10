#!/usr/bin/env python3
"""Convert the reproducible llama.cpp probe dumps into the PACT layout the
stage-parity comparator expects (ref_l%02d_p%02d_<stage>.bin).
"""
import os
import re
import struct
import sys

SRC = sys.argv[1] if len(sys.argv) > 1 else \
    r"F:\rawrxd\evidence\RAWRXD_REFERENCE_REPRODUCIBILITY_001\ref_stages"
DST = sys.argv[2] if len(sys.argv) > 2 else \
    r"F:\rawrxd\evidence\RAWRXD_REFERENCE_REPRODUCIBILITY_001\ref_capture_repro"

NAME_MAP = {
    "q": "q",
    "attn_norm": "attn_norm",
    "attn_out": "attn_out",
    "ffn_norm": "ffn_norm",
    "ffn_out": "ffn_out",
    "ffn_moe_out": "ffn_moe_out",
    "kv_cmpr_used": "kv_cmpr",
    "k_pe": "k_pe",
    "kq_soft_max": None,  # weights, not an activation
}


def read_raw(path):
    raw = open(path, "rb").read()
    assert raw[:4] == b"RAWH"
    ne = struct.unpack("<4q", raw[4:36])
    n_rows = 1
    for d in range(1, 4):
        n_rows *= ne[d]
    v = np_bytes(raw[68:], n_rows, ne[0])
    return ne, v


def np_bytes(buf, n_rows, row_len):
    import array
    a = array.array("f")
    a.frombytes(buf[: n_rows * row_len * 4])
    return a.tolist()


def write_pact(path, layer, stage, ne, values):
    with open(path, "wb") as f:
        f.write(struct.pack("<I", 0x54434150))          # PACT
        f.write(struct.pack("<I", 1))                    # version
        f.write(struct.pack("<Q", layer))
        name = stage.encode()
        f.write(struct.pack("<I", len(name)))
        f.write(name)
        dims = [ne[0]]
        n = ne[0]
        for d in range(1, 4):
            if ne[d] > 1:
                dims.append(ne[d])
                n *= ne[d]
        f.write(struct.pack("<I", len(dims)))
        for d in dims:
            f.write(struct.pack("<Q", d))
        f.write(struct.pack("<%df" % len(values), *values))


def main():
    os.makedirs(DST, exist_ok=True)
    n = 0
    for fn in sorted(os.listdir(SRC)):
        m = re.match(r"probe_step(\d+)_(.+?)_l(-?\d+)\.bin$", fn)
        if not m:
            continue
        pos = int(m.group(1))
        stage = NAME_MAP.get(m.group(2))
        if stage is None:
            continue
        layer = int(m.group(3))
        ne, values = read_raw(os.path.join(SRC, fn))
        # the reference dumps were keyed by llama layer index; l-1 is the tail
        layer_key = 4294967295 if layer < 0 else layer
        out = os.path.join(DST, "ref_l%02d_p%02d_%s.bin" % (layer, pos, stage)) \
            if layer >= 0 else os.path.join(DST, "ref_l-1_p%02d_%s.bin" % (pos, stage))
        write_pact(out, layer_key, stage, ne, values)
        n += 1
    print("converted %d files -> %s" % (n, DST))
    return 0


if __name__ == "__main__":
    sys.exit(main())
