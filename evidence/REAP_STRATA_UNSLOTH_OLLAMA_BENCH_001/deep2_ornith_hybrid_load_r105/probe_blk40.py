import struct
p = r"F:\OllamaModels\_REAP16\ornith-1_5-35b-REAP194\sha256-aaeb640f98a892980ef54876024293cc8d6987a86523aa1b947ffa9274ef800a"
with open(p, "rb") as f:
    magic = f.read(4)
    ver = struct.unpack("<I", f.read(4))[0]
    n_tv, n_kv = struct.unpack("<QQ", f.read(16))

    def rstr():
        n = struct.unpack("<Q", f.read(8))[0]
        return f.read(n).decode("utf-8", "replace")

    def rval(t):
        if t == 4:
            return struct.unpack("<Q", f.read(8))[0]
        if t == 5:
            return struct.unpack("<q", f.read(8))[0]
        if t == 6:
            return struct.unpack("<f", f.read(4))[0]
        if t == 7:
            return struct.unpack("?", f.read(1))[0]
        if t == 8:
            return rstr()
        if t == 9:
            et, n = struct.unpack("<IQ", f.read(12))
            return [rval(et) for _ in range(n)]
        if t == 10:
            return struct.unpack("<d", f.read(8))[0]
        if t == 11:
            return struct.unpack("<I", f.read(4))[0]
        if t == 12:
            return struct.unpack("<i", f.read(4))[0]
        raise SystemExit("bad t %d" % t)

    for _ in range(n_kv):
        k = rstr()
        t = struct.unpack("<I", f.read(4))[0]
        v = rval(t)
    names = []
    for _ in range(n_tv):
        name = rstr()
        nd = struct.unpack("<I", f.read(4))[0]
        dims = [struct.unpack("<Q", f.read(8))[0] for __ in range(nd)]
        typ = struct.unpack("<I", f.read(4))[0]
        off = struct.unpack("<Q", f.read(8))[0]
        if name.startswith("blk.40.") or name.startswith("blk.39.") or name.startswith("blk.38."):
            names.append(name)
print("count", len(names))
for n in names:
    print(n)
print("attn_q40", any(n == "blk.40.attn_q.weight" for n in names))
print("ffn_gate_inp40", any("ffn_gate_inp" in n for n in names if n.startswith("blk.40.")))
print("ssm40", any("ssm" in n for n in names if n.startswith("blk.40.")))
