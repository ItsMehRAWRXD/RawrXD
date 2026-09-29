#!/usr/bin/env python3
"""Decode the engine's generated token using the GGUF vocab (streaming)."""
import struct

GGUF = r"F:\models\Qwen2.5-Coder-32B-Instruct-Q4_K_M.gguf"
WANT_ID = 82

f = open(GGUF, "rb")
magic = f.read(4)
version = struct.unpack("<I", f.read(4))[0]
n_tensors = struct.unpack("<Q", f.read(8))[0]
n_kv = struct.unpack("<Q", f.read(8))[0]


def read_str(fh):
    n = struct.unpack("<Q", fh.read(8))[0]
    data = fh.read(n)
    return data.decode("utf-8", "replace")


def skip_value(fh, t):
    fixed = {0: 1, 1: 1, 2: 2, 3: 4, 4: 4, 5: 8, 7: 16, 6: 8}
    if t in fixed:
        fh.read(fixed[t])
    elif t == 8:
        read_str(fh)
    elif t in (9, 10):
        et = struct.unpack("<I", fh.read(4))[0]
        n = struct.unpack("<Q", fh.read(8))[0]
        for _ in range(n):
            skip_value(fh, et)


found = None
for _ in range(n_kv):
    key = read_str(f)
    t = struct.unpack("<I", f.read(4))[0]
    if key == "tokenizer.ggml.tokens":
        et = struct.unpack("<I", f.read(4))[0]
        n = struct.unpack("<Q", f.read(8))[0]
        print("VOCAB_ARRAY type=", et, "n=", n)
        # stream to the wanted id
        for i in range(n):
            s = read_str(f)
            if i == WANT_ID:
                found = s
                break
        break
    skip_value(f, t)
f.close()
print("TOKEN", WANT_ID, "=", repr(found))