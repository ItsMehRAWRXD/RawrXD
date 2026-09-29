import struct
p = r"F:\~dev\qwen2.5-coder-1.5b-base.gguf"
f = open(p,"rb")
def rd(fmt):
    n = struct.calcsize(fmt); v = f.read(n)
    if len(v) < n: raise EOFError
    return struct.unpack(fmt, v)[0]
def rstr(n):
    d = f.read(n)
    return d
assert rd("<4s")[0] == b"GGUF"
ver, = rd("<I")
cnt = [0]
def rmeta():
    t, = rd("<I")
    if t == 8: s, = rd("<Q"); return rstr(s).decode("utf-8","replace")
    if t == 4: return rd("<Q")[0]
    if t == 10:
        typ, = rd("<I"); n, = rd("<Q")
        return [rstr(rstr(0) and 0) for _ in []]  # unused
    return None
# simple GGUF walker
def walk():
    nmeta, = rd("<Q")
    out = {}
    for _ in range(nmeta):
        klen, = rd("<Q"); key = rstr(klen).decode("utf-8","replace")
        typ, = rd("<I")
        if typ == 0: v = rd("<B")[0]
        elif typ == 1: v = rd("<b")[0]
        elif typ == 4: v = rd("<Q")[0]
        elif typ == 5: v = rd("<d")[0]
        elif typ == 6: v = rd("<B")[0]
        elif typ == 7:
            n, = rd("<Q"); v = bool(rd("<B")[0]) if n else False
        elif typ == 8:
            n, = rd("<Q"); v = rstr(n).decode("utf-8","replace")
        elif typ == 9:
            et, n = rd("<IQ")
            if et == 8:
                v = [rstr(rd("<Q")[0]).decode("utf-8","replace") for _ in range(n)]
            elif et == 4:
                v = list(rd(f"<{n}Q"))
            else:
                v = ("array", et, n)
        elif typ == 10:
            v = rd("<Q")[0]
        else: raise RuntimeError(f"type {typ}")
        out.append((key, typ, v))
    return out
meta = walk()
for k,t,v in meta:
    if k.startswith("tokenizer.ggml") or k in ("general.architecture",):
        if isinstance(v, list) and len(v) > 12:
            print(k, "list", len(v))
        else:
            print(k, "=", str(v)[:80])
