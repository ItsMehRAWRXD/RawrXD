import struct
f = open(r"F:\~dev\qwen2.5-coder-1.5b-base.gguf", "rb")
f.read(4); struct.unpack("<I", f.read(4))[0]
n_tensors = struct.unpack("<Q", f.read(8))[0]
n_kv = struct.unpack("<Q", f.read(8))[0]
def read_str():
    n = struct.unpack("<Q", f.read(8))[0]
    return f.read(n).decode("utf-8", "replace")
def skip_value(t):
    if t == 8: read_str()
    elif t in (0,1,7): f.seek(1,1)
    elif t in (2,3): f.seek(2,1)
    elif t in (4,5,6): f.seek(4,1)
    elif t in (10,11,12): f.seek(8,1)
    elif t == 9:
        et = struct.unpack("<I", f.read(4))[0]
        n = struct.unpack("<Q", f.read(8))[0]
        for _ in range(n): skip_value(et)
for _ in range(n_kv):
    k = read_str(); t = struct.unpack("<I", f.read(4))[0]
    if k in ("qwen2.context_length","context_length","{0}.context_length".format("qwen2")):
        if t == 4: print(k, "=", struct.unpack("<I", f.read(4))[0])
        elif t == 10: print(k, "=", struct.unpack("<Q", f.read(8))[0])
        elif t == 5: print(k, "=", struct.unpack("<f", f.read(4))[0])
    else:
        skip_value(t)
f.close()
