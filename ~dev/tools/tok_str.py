# tok_str.py -- print the tokenizer strings for chosen token IDs,
# so llama.cpp's CLI can be fed an exact single-token prompt.
import struct
import sys

MODEL = r"F:\rawrxd\models\qwen2.5-coder_1.5b-base.gguf"
WANT = [750, 5290, 304, 1875, 374, 220, 1887, 3932, 262, 1173, 445]

with open(MODEL, "rb") as fh:
    magic, version, tcount, kvcount = struct.unpack("<4sIQQ", fh.read(24))
    assert magic == b"GGUF"
    toks = None
    for _ in range(kvcount):
        klen = struct.unpack("<Q", fh.read(8))[0]
        key = fh.read(klen).decode("utf-8", "replace")
        vtype = struct.unpack("<I", fh.read(4))[0]
        if vtype == 8:
            n = struct.unpack("<Q", fh.read(8))[0]
            val = fh.read(n)
        elif vtype == 9:
            etype = struct.unpack("<I", fh.read(4))[0]
            count = struct.unpack("<Q", fh.read(8))[0]
            if etype == 8:
                val = []
                for _ in range(count):
                    n = struct.unpack("<Q", fh.read(8))[0]
                    val.append(fh.read(n))
            else:
                fmtc = {0:("B",1),1:("b",1),2:("H",2),3:("h",2),4:("I",4),
                        5:("i",4),6:("f",4),7:("?",1),10:("Q",8),11:("q",8),
                        12:("d",8)}
                c, esz = fmtc[etype]
                val = list(struct.unpack(f"<{count}{c}", fh.read(esz*count)))
        else:
            fmtc = {0:("B",1),1:("b",1),2:("H",2),3:("h",2),4:("I",4),
                    5:("i",4),6:("f",4),7:("?",1),10:("Q",8),11:("q",8),
                    12:("d",8)}
            c, esz = fmtc[vtype]
            val = struct.unpack(f"<{c}", fh.read(esz))[0]
        if key == "tokenizer.ggml.tokens":
            toks = val
    if toks is None:
        sys.exit("tokens array not found")

print(f"n_tokens={len(toks)}")
for t in WANT:
    if 0 <= t < len(toks):
        b = toks[t]
        try:
            s = b.decode("utf-8")
        except UnicodeDecodeError:
            s = b.decode("utf-8", "replace")
        print(f"{t:6d}  bytes={b!r}  str={s!r}")
