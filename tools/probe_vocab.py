#!/usr/bin/env python3
"""GGUF vocab probe - RAWRXD tokenizer parity

Reads the SentencePiece token array straight out of the GGUF and reports
whether the metaspace marker, byte-fallback tokens and typical words are
present, so tokenizer encoding failures can be attributed precisely.
"""
import struct
import sys

GGUF_MAGIC = 0x46554747
TS = {0: 1, 1: 1, 2: 2, 3: 2, 4: 4, 5: 4, 6: 4, 7: 1, 10: 8, 11: 8, 12: 8}


def main():
    d = open(sys.argv[1], "rb").read()
    n_tensors, n_kv = struct.unpack_from("<QQ", d, 8)
    p = 24

    def rs(p):
        (n,) = struct.unpack_from("<Q", d, p)
        p += 8
        return d[p:p + n], p + n

    def skip(t, p):
        if t == 8:
            _, p = rs(p)
            return p
        if t == 9:
            (et,) = struct.unpack_from("<I", d, p)
            p += 4
            (c,) = struct.unpack_from("<Q", d, p)
            p += 8
            for _ in range(c):
                p = skip(et, p)
            return p
        if t not in TS:
            raise ValueError("type %d" % t)
        return p + TS[t]

    meta = {}
    for _ in range(n_kv):
        k, p = rs(p)
        (t,) = struct.unpack_from("<I", d, p)
        p += 4
        key = k.decode("utf-8", "replace")
        start = p
        p = skip(t, p)
        if t == 8:
            meta[key] = rs(start)[0].decode("utf-8", "replace")
        elif t == 4:
            meta[key] = struct.unpack_from("<I", d, start)[0]
        elif t == 5:
            meta[key] = struct.unpack_from("<i", d, start)[0]
        elif t == 6:
            meta[key] = struct.unpack_from("<f", d, start)[0]
        elif t == 9:
            (et,) = struct.unpack_from("<I", d, start)
            (c,) = struct.unpack_from("<Q", d, start + 4)
            q = start + 12
            vals = []
            if et == 8:
                for _ in range(min(c, 4)):
                    v, q = rs(q)
                    vals.append(v.decode("utf-8", "replace")[:20])
            meta[key] = {"elem_type": et, "count": c, "first": vals}

    print("n_tensors=%d  n_kv=%d" % (n_tensors, n_kv))
    for k in sorted(meta):
        v = meta[k]
        s = str(v)[:110] if not isinstance(v, dict) else \
            "array elem=%s count=%s first=%s" % (v["elem_type"], v["count"], v["first"])
        if k.startswith(("tokenizer", "general", "deepseek2.rope")) and "tokens" not in k and "tokens_" not in k:
            print("  %-52s = %s" % (k, s))

    # Tokens array is large; locate it explicitly.
    tokens_key = "tokenizer.ggml.tokens"
    p = 24
    for _ in range(n_kv):
        k, p = rs(p)
        (t,) = struct.unpack_from("<I", d, p)
        p += 4
        if t == 9 and k.decode() == tokens_key:
            (et,) = struct.unpack_from("<I", d, p)
            (c,) = struct.unpack_from("<Q", d, p + 4)
            q = p + 12
            toks = []
            for _ in range(c):
                (n,) = struct.unpack_from("<Q", d, q)
                q += 8
                toks.append(d[q:q + n])
                q += n
            print("\n%s: %d tokens, elem_type=%d" % (tokens_key, len(toks), et))
            index = {t: i for i, t in enumerate(toks)}
            for probe in [b"\xe2\x96\x81", b"\xe2\x96\x81Human", b"Human",
                          b"Hello", b"world!", b"A", b"chat", b"the", b"!"]:
                print("  %-14r present=%s id=%s" %
                      (probe, probe in index, index.get(probe, "-")))
            bf = [i for i, t in enumerate(toks) if t.startswith(b"<0x")]
            print("  byte-fallback (<0xNN>) tokens: %d, first=%s" %
                  (len(bf), toks[bf[0]][:12] if bf else None))
            ctrl = [i for i, t in enumerate(toks) if t.startswith(b"<|")]
            print("  <|...|> special tokens: %d, first=%s" %
                  (len(ctrl), toks[ctrl[0]][:16] if ctrl else None))
            print("  token['Ã']: id=%s" % index.get(b"\xc3\xa1", "-"))
            print("  id 0..4 = %r" % toks[:5])
            return
        p = skip(t, p)
    print("\n%s not found" % tokens_key)


if __name__ == "__main__":
    main()
