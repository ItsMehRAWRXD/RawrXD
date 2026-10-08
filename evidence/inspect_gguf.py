import struct, sys

PATH = r"G:\~dev\rawrxd\models\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf"
SIZE = 1024 * 1024  # 1 MiB head is plenty for header+metadata+tensor info start

def ru64(d, p): return struct.unpack_from("<Q", d, p)[0]
def ru32(d, p): return struct.unpack_from("<I", d, p)[0]

with open(PATH, "rb") as f:
    d = f.read(SIZE)

print(f"Read {len(d)} bytes")
p = 0
magic = ru32(d, p); p += 4
ver = ru32(d, p); p += 4
tcount = ru64(d, p); p += 8
mkv = ru64(d, p); p += 8
print(f"magic={magic:#010x} ver={ver} tensor_count={tcount} metadata_kv_count={mkv}")

# GGUF value types per src/gguf.h: 0..7,8=string,9=array,10=u64,11=i64,12=f64
SCALAR = {0:1,1:1,2:2,3:2,4:4,5:4,6:4,7:1,10:8,11:8,12:8}

ok = True
shown = 0
for i in range(mkv):
    if p+8 > len(d): print(f"KV[{i}] FAIL no keylen at {p}"); ok=False; break
    klen = ru64(d, p); p += 8
    if p+klen > len(d): print(f"KV[{i}] FAIL keylen={klen} at {p}"); ok=False; break
    key = d[p:p+klen].decode("utf-8","replace"); p += klen
    if p+4 > len(d): print(f"KV[{i}] FAIL notype key={key!r}"); ok=False; break
    vt = ru32(d, p); p += 4
    if vt in SCALAR:
        sz = SCALAR[vt]
        if p+sz > len(d): print(f"KV[{i}] FAIL scalar at {p} type={vt} key={key!r}"); ok=False; break
        p += sz
    elif vt == 8:  # string: uint64 len + bytes
        if p+8 > len(d): print(f"KV[{i}] FAIL strlen at {p} key={key!r}"); ok=False; break
        sl = ru64(d, p); p += 8
        if p+sl > len(d): print(f"KV[{i}] FAIL stringdata at {p} len={sl} key={key!r}"); ok=False; break
        p += sl
    elif vt == 9:  # array: elem_type(int32) + count(uint64) + elements
        if p+4 > len(d): print(f"KV[{i}] FAIL arrelemtype at {p} key={key!r}"); ok=False; break
        et = ru32(d, p); p += 4
        if p+8 > len(d): print(f"KV[{i}] FAIL arrcount at {p} key={key!r}"); ok=False; break
        cnt = ru64(d, p); p += 8
        if et in SCALAR:
            esz = SCALAR[et]; need = cnt*esz
            if p+need > len(d): print(f"KV[{i}] FAIL arraydata at {p} et={et} cnt={cnt} key={key!r}"); ok=False; break
            p += need
        elif et == 8:  # array of strings: each is uint64 len + bytes
            bad=False
            for _ in range(cnt):
                if p+8>len(d): print(f"KV[{i}] FAIL arrelemstrlen at {p} key={key!r}"); bad=True; ok=False; break
                esl=ru64(d,p); p+=8
                if p+esl>len(d): print(f"KV[{i}] FAIL arrelemstr at {p} len={esl} key={key!r}"); bad=True; ok=False; break
                p+=esl
            if bad: break
        else:
            print(f"KV[{i}] FAIL unknown array elem_type={et} key={key!r}"); ok=False; break
    else:
        print(f"KV[{i}] FAIL unknown value_type={vt} key={key!r}"); ok=False; break
    if shown < 60 or vt == 9:
        print(f"KV[{i}] key={key!r} type={vt}")
    elif shown == 60:
        print("... (remaining KVs skipped for brevity) ..."); shown += 1

print(f"\n=== metadata skip: ok={ok}, final ptr={p} (0x{p:x}) ===")
if p+8 <= len(d):
    nxt = ru64(d, p)
    print(f"Next 8 bytes as uint64: {nxt}  (header.tensor_count={tcount})")
    # try interpret as tensor name length
    if 0 < nxt < 256 and p+8+nxt < len(d):
        nm = d[p+8:p+8+nxt]
        print(f"Interpret next-as-name: len={nxt} name={nm!r}")
    print(f"Bytes at ptr (hex): {d[p:p+40].hex()}")
# Walk a few tensors to validate type IDs
print("\n--- tensor info preview ---")
tp = p
# GGUF v3 tensor info: possibly a redundant uint64 count then reserved? Probe.
# Try as if NO redundant count (token0/gguf_inspector model):
import re as _re
for ti in range(min(tcount, 5)):
    try:
        if tp+8 > len(d): print(f"T[{ti}] FAIL nameLen at {tp}"); break
        nlen = ru64(d, tp); tp += 8
        if tp+nlen > len(d): print(f"T[{ti}] FAIL name at {tp} len={nlen}"); break
        name = d[tp:tp+nlen].decode("utf-8","replace"); tp += nlen
        if tp+4 > len(d): print(f"T[{ti}] FAIL ndims at {tp}"); break
        nd = ru32(d, tp); tp += 4
        dims = []
        for _ in range(nd):
            if tp+8>len(d): break
            dims.append(ru64(d, tp)); tp += 8
        if tp+4 > len(d): print(f"T[{ti}] FAIL type at {tp}"); break
        ttype = ru32(d, tp); tp += 4
        if tp+8 > len(d): print(f"T[{ti}] FAIL offset at {tp}"); break
        doff = ru64(d, tp); tp += 8
        print(f"T[{ti}] name={name!r} ndims={nd} dims={dims} type={ttype} offset={doff}")
    except Exception as e:
        print(f"T[{ti}] EXC {e} at {tp}"); break
