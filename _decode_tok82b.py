import struct
GGUF = r"F:\models\Qwen2.5-Coder-32B-Instruct-Q4_K_M.gguf"
WANT_ID = 82
f = open(GGUF, "rb")
f.read(4)
struct.unpack("<I", f.read(4))
n_tensors = struct.unpack("<Q", f.read(8))[0]
n_kv = struct.unpack("<Q", f.read(8))[0]
def read_str(fh):
    n = struct.unpack("<Q", fh.read(8))[0]
    return fh.read(n).decode("utf-8", "replace")
def skip_value(fh, t):
    if t == 8:
        read_str(fh)
    elif t in (0, 1, 7):
        fh.seek(1, 1)
    elif t in (2, 3):
        fh.seek(2, 1)
    elif t in (4, 5, 6):
        fh.seek(4, 1)
    elif t in (10, 11, 12):
        fh.seek(8, 1)
    elif t == 9:
        et = struct.unpack("<I", fh.read(4))[0]
        n = struct.unpack("<Q", fh.read(8))[0]
        for _ in range(n):
            skip_value(fh, et)
    else:
        raise ValueError(t)
found = None
for _ in range(n_kv):
    key = read_str(f)
    t = struct.unpack("<I", f.read(4))[0]
    if key == "tokenizer.ggml.tokens" and t == 9:
        et = struct.unpack("<I", f.read(4))[0]
        n = struct.unpack("<Q", f.read(8))[0]
        print("VOCAB_ARRAY et=", et, "n=", n)
        for i in range(n):
            s = read_str(f)
            if i == WANT_ID:
                found = s
                break
        break
    else:
        skip_value(f, t)
f.close()
print("TOKEN", WANT_ID, "=", repr(found))
