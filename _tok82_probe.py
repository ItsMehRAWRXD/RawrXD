#!/usr/bin/env python3
"""Decode token 82 from the 32B GGUF vocab (streaming, low memory)."""
import struct

GGUF = r"F:\models\Qwen2.5-Coder-32B-Instruct-Q4_K_M.gguf"

f = open(GGUF, "rb")
f.read(4)
struct.unpack("<I", f.read(4))
n_tensors = struct.unpack("<Q", f.read(8))[0]
n_kv = struct.unpack("<Q", f.read(8))[0]


def read_str(fh):
    n = struct.unpack("<Q", fh.read(8))[0]
    return fh.read(n).decode("utf-8", "replace")


def skip_value(fh, t):
    if t == 0:
        fh.read(1)
    elif t == 1:
        fh.read(1)
    elif t == 2:
        fh.read(2)
    elif t == 3:
        fh.read(4)
    elif t == 4:
        fh.read(4)
    elif t == 5:
        fh.read(8)
    elif t == 8:
        read_str(fh)
    elif t == 6:
        fh.read(8)
    elif t == 7:
        t2 = struct.unpack("<I", fh.read(4))[0]
        n2 = struct.unpack("<Q", fh.read(8))[0]
        for _ in range(n2):
            skip_value(fh, t2)
    elif t == 9:
        t2 = struct.unpack("<I", fh.read(4))[0]
        n2 = struct.unpack("<Q", fh.read(8))[0]
        for _ in range(n2):
            skip_value(fh, t2)
    elif t == 10:
        t2 = struct.unpack("<I", fh.read(4))[0]
        n2 = struct.unpack("<Q", fh.read(8))[0]
        for _ in range(n2):
            skip_value(fh, t2)


toks = []
found = False
for _ in range(n_kv):
    k = read_str(f)
    t = struct.unpack("<I", f.read(4))[0]
    if k == "tokenizer.ggml.tokens":
        t2 = struct.unpack("<I", f.read(4))[0]
        n2 = struct.unpack("<Q", f.read(8))[0]
        print("VOCAB_N =", n2, "TYPE =", t2)
        for i in range(n2):
            s = read_str(f)
            if i < 100:
                toks.append(s)
            if i == 99:
                found = True
                break
        break
    else:
        skip_value(f, t)
f.close()

if found:
    print("TOKEN82 =", repr(toks[82]))
    print("NEIGHBORS =", [repr(x) for x in toks[78:88]])
else:
    print("VOCAB_TOKENS_KEY_NOT_FOUND_BEFORE_SLICE_END", len(toks))