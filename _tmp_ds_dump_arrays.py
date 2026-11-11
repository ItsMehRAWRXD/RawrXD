"""Dump DeepSeek GGUF tokenizer arrays (metadata region only) to compact files
for the C++ parity harness. Writes into the same folder as this script by default:
  ds_tokens.bin  [u32 count]{ [u32 len][bytes] }*
  ds_scores.bin  [u32 count]{ f32 }*
  ds_merges.bin  [u32 count]{ [u32 len][bytes] }*
  ds_types.bin   [u32 count]{ i32 }*
  ds_meta.txt    key=value lines
"""
import struct
import sys
import os

UINT8, INT8, UINT16, INT16, UINT32, INT32, FLOAT32, BOOL, STRING, ARRAY, UINT64, INT64, FLOAT64 = range(13)
SCALAR_SZ = {UINT8: 1, INT8: 1, UINT16: 2, INT16: 2, UINT32: 4, INT32: 4,
             FLOAT32: 4, BOOL: 1, UINT64: 8, INT64: 8, FLOAT64: 8}

GGUF = sys.argv[1] if len(sys.argv) > 1 else r"F:\rawrxd\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf"
OUT = sys.argv[2] if len(sys.argv) > 2 else os.path.dirname(os.path.abspath(__file__))


class R:
    def __init__(self, path):
        self.f = open(path, "rb")
        self.pos = 0

    def read(self, n):
        b = self.f.read(n)
        self.pos += len(b)
        return b

    def seek(self, n):
        self.pos += n
        self.f.seek(self.pos)

    def u64(self): return struct.unpack("<Q", self.read(8))[0]
    def i64(self): return struct.unpack("<q", self.read(8))[0]
    def i32(self): return struct.unpack("<i", self.read(4))[0]
    def u32(self): return struct.unpack("<I", self.read(4))[0]
    def f32(self): return struct.unpack("<f", self.read(4))[0]

    def s(self):
        n = self.u64()
        return self.read(n)

    def skip(self, t):
        if t in SCALAR_SZ:
            self.seek(SCALAR_SZ[t]); return
        if t == STRING:
            self.seek(self.u64()); return
        if t == ARRAY:
            et = self.u32(); cnt = self.u64()
            for _ in range(cnt):
                self.skip(et)
            return
        raise ValueError("bad type %d" % t)


def main():
    r = R(GGUF)
    r.u32(); r.u32(); r.u64()  # magic, version, n_tensors
    n_kv = r.u64()

    tokens = scores = merges = ttypes = None
    meta = {}

    for _ in range(n_kv):
        key = r.s().decode("utf-8", "replace")
        vtype = r.u32()
        if vtype == STRING:
            meta[key] = r.s().decode("utf-8", "replace")
        elif vtype in (INT32, UINT32):
            v = r.i32()
            meta[key] = v
            # keep reading nothing else
        elif vtype in (BOOL, INT8, UINT8):
            meta[key] = r.read(SCALAR_SZ[vtype])[0]
        elif vtype in (UINT64, INT64):
            meta[key] = r.u64()
        elif vtype == FLOAT32:
            meta[key] = r.f32()
        elif vtype == ARRAY:
            et = r.u32(); cnt = r.u64()
            if key == "tokenizer.ggml.tokens":
                tokens = [r.s() for _ in range(cnt)]
            elif key == "tokenizer.ggml.scores" and et == FLOAT32:
                scores = [r.f32() for _ in range(cnt)]
            elif key == "tokenizer.ggml.merges":
                merges = [r.s() for _ in range(cnt)]
            elif key == "tokenizer.ggml.token_type" and et == INT32:
                ttypes = [r.i32() for _ in range(cnt)]
            else:
                for _ in range(cnt):
                    r.skip(et)
        else:
            r.skip(vtype)

    if tokens is None:
        print("tokens not found"); return 1

    def w_lp(path, items):
        with open(path, "wb") as o:
            o.write(struct.pack("<I", len(items)))
            for it in items:
                o.write(struct.pack("<I", len(it)))
                o.write(it)

    w_lp(os.path.join(OUT, "ds_tokens.bin"), tokens)
    if scores:
        with open(os.path.join(OUT, "ds_scores.bin"), "wb") as o:
            o.write(struct.pack("<I", len(scores)))
            for s in scores:
                o.write(struct.pack("<f", s))
    if merges:
        w_lp(os.path.join(OUT, "ds_merges.bin"), merges)
    if ttypes:
        with open(os.path.join(OUT, "ds_types.bin"), "wb") as o:
            o.write(struct.pack("<I", len(ttypes)))
            for t in ttypes:
                o.write(struct.pack("<i", t))

    keep = {k: meta[k] for k in meta if k.startswith(("tokenizer", "general"))}
    with open(os.path.join(OUT, "ds_meta.txt"), "w", encoding="utf-8") as o:
        for k in sorted(keep):
            o.write("%s=%s\n" % (k, keep[k]))

    print("tokens=%d scores=%s merges=%s types=%s" %
          (len(tokens), len(scores) if scores else 0,
           len(merges) if merges else 0, len(ttypes) if ttypes else 0))
    print("wrote to", OUT)
    return 0


if __name__ == "__main__":
    sys.exit(main())
