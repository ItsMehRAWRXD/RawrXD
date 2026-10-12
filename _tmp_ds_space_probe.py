"""DeepSeek-V2-Lite GGUF encoded-space probe (TOKENIZER-PARITY diagnostic).

Streams only the GGUF metadata (never the 10 GB tensor payload) and reports how
whitespace is represented in the token vocabulary:
  - U+0120 'G'  (GPT-2 byte-level space)          -> bytes c4 a0
  - U+2581 '_'  (SentencePiece metaspace)         -> bytes e2 96 81
  - literal ASCII space (0x20)

Then it resolves a set of reference token IDs to their raw text so the encoded
space symbol can be identified directly.
"""
import struct
import sys

UINT8, INT8, UINT16, INT16, UINT32, INT32, FLOAT32, BOOL, STRING, ARRAY, UINT64, INT64, FLOAT64 = range(13)
SCALAR_SZ = {UINT8: 1, INT8: 1, UINT16: 2, INT16: 2, UINT32: 4, INT32: 4,
             FLOAT32: 4, BOOL: 1, UINT64: 8, INT64: 8, FLOAT64: 8}

G = b"\xc4\xa0"          # U+0120  (bytes of GPT-2 'G' space)
USP = b"\xe2\x96\x81"    # U+2581 SentencePiece underscore
SP = b" "                # 0x20 literal space


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

    def u64(self):  return struct.unpack("<Q", self.read(8))[0]
    def i64(self):  return struct.unpack("<q", self.read(8))[0]
    def i32(self):  return struct.unpack("<i", self.read(4))[0]
    def u32(self):  return struct.unpack("<I", self.read(4))[0]

    def s(self):
        n = self.u64()
        return self.read(n)

    def scalar(self, t):
        self.seek(SCALAR_SZ[t])

    def skip(self, t):
        if t in SCALAR_SZ:
            self.seek(SCALAR_SZ[t])
            return
        if t == STRING:
            self.seek(self.u64())
            return
        if t == ARRAY:
            et = self.u32()
            cnt = self.u64()
            for _ in range(cnt):
                self.skip(et)
            return
        raise ValueError("bad type %d at %d" % (t, self.pos))


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else r"F:\rawrxd\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf"
    r = R(path)
    magic = r.u32()
    version = r.u32()
    n_tensors = r.u64()
    n_kv = r.u64()
    print("magic=0x%08x version=%d n_tensors=%d n_kv=%d" % (magic, version, n_tensors, n_kv))

    strings = {}
    tokens = None
    score_present = False

    for _ in range(n_kv):
        key = r.s().decode("utf-8", "replace")
        vtype = r.u32()
        if vtype == STRING:
            strings[key] = r.s()
        elif vtype == ARRAY:
            et = r.u32()
            cnt = r.u64()
            if key == "tokenizer.ggml.tokens" and et == STRING:
                toks = []
                for _ in range(cnt):
                    n = r.u64()
                    toks.append(r.read(n))
                tokens = toks
            elif et == STRING:
                # skip (but record count for large arrays such as merges)
                strings[key] = ("<array:%d>" % cnt)
                for _ in range(cnt):
                    r.seek(r.u64())
            else:
                for _ in range(cnt):
                    r.skip(et)
        elif vtype in SCALAR_SZ:
            strings[key] = r.read(SCALAR_SZ[vtype])
            if vtype == ARRAY:
                pass
        else:
            raise ValueError("bad vtype %d for %s" % (vtype, key))

    # --- tokenizer identity metadata ---
    print("\n=== tokenizer metadata ===")
    for k in ("tokenizer.ggml.pre", "tokenizer.ggml.model",
              "tokenizer.ggml.add_bos_token", "tokenizer.ggml.add_eos_token",
              "general.architecture"):
        if k in strings:
            v = strings[k]
            print("  %-34s = %r" % (k, v))

    if tokens is None:
        print("tokenizer.ggml.tokens NOT FOUND")
        return 1

    n = len(tokens)
    print("\n=== token array: %d tokens ===" % n)

    idx = {}
    for i, t in enumerate(tokens):
        idx.setdefault(t, i)

    # Encoded-space representation counts
    c_g    = sum(1 for t in tokens if G in t)
    c_usp  = sum(1 for t in tokens if USP in t)
    c_lit  = sum(1 for t in tokens if SP in t)
    c_gpre = sum(1 for t in tokens if t.startswith(G))
    c_lpre = sum(1 for t in tokens if t.startswith(SP))
    print("tokens containing  'G'(U+0120) : %d" % c_g)
    print("tokens containing  '_' (U+2581) : %d" % c_usp)
    print("tokens containing  ' '(0x20)    : %d" % c_lit)
    print("tokens STARTING with 'G'(U+0120): %d" % c_gpre)
    print("tokens STARTING with ' '(0x20)  : %d" % c_lpre)

    # Exact symbol lookups (the user's requested check)
    print("\n=== encoded-space symbol presence (count of matching tokens) ===")
    for label, sym in (("G", G), ("_", USP), ("space", SP)):
        matches = [(i, tokens[i]) for i in range(n) if sym in tokens[i]]
        print("symbol %-6r count=%d  first=%s" %
              (label, len(matches),
               [tokens[i] for i, _ in matches[:8]]))

    # Direct probe tokens for "the"/"chat"/"Hello"
    print("\n=== direct vocab lookups for 'the'/'chat'/'Hello' with each space encoding ===")
    for probe in (G + b"the", SP + b"the", USP + b"the",
                  G + b"chat", SP + b"chat", USP + b"chat",
                  b"Hello", G + b"Hello", SP + b"Hello",
                  G + b" the", b" the"):
        print("  %-16r id=%s" % (probe, idx.get(probe, "ABSENT")))

    # Resolve reference IDs from ggml-vocab-deepseek-llm.gguf.out
    print("\n=== reference token IDs resolved to raw text ===")
    for tid in (0, 1, 2, 3, 4, 17464, 37727, 1843, 207, 185):
        if 0 <= tid < n:
            t = tokens[tid]
            shown = t.decode("utf-8", "replace")
            print("  id %-6d = %-16r  utf8=%r  hex=%s" % (tid, t, shown, t.hex()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
