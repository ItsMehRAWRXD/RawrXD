import struct,re
p=r"F:\OllamaModels\_REAP16\ornith-1_5-35b-REAP194\sha256-aaeb640f98a892980ef54876024293cc8d6987a86523aa1b947ffa9274ef800a"
with open(p,"rb") as f:
    magic=f.read(4); ver=struct.unpack("<I",f.read(4))[0]
    n_tensors,n_kv=struct.unpack("<QQ",f.read(16))
    def rstr():
        n=struct.unpack("<Q",f.read(8))[0]
        return f.read(n)
    def rval(t):
        if t==0: return struct.unpack("<B",f.read(1))[0]
        if t==1: return struct.unpack("<b",f.read(1))[0]
        if t==2: return struct.unpack("<H",f.read(2))[0]
        if t==3: return struct.unpack("<h",f.read(2))[0]
        if t==4: return struct.unpack("<I",f.read(4))[0]
        if t==5: return struct.unpack("<i",f.read(4))[0]
        if t==6: return struct.unpack("<f",f.read(4))[0]
        if t==7: return bool(f.read(1)[0])
        if t==8: return rstr().decode("utf-8","replace")
        if t==9:
            nt,n=struct.unpack("<IQ",f.read(12)); return [rval(nt) for _ in range(n)]
        if t==10: # array of arrays?
            raise SystemExit("t10")
        raise SystemExit("t"+str(t))
    kvs={}
    for _ in range(n_kv):
        k=rstr().decode("utf-8","replace"); t=struct.unpack("<I",f.read(4))[0]; kvs[k]=rval(t)
    names=[]
    for _ in range(n_tensors):
        name=rstr().decode("utf-8","replace")
        nd=struct.unpack("<I",f.read(4))[0]
        dims=[struct.unpack("<Q",f.read(8))[0] for __ in range(nd)]
        typ=struct.unpack("<I",f.read(4))[0]
        off=struct.unpack("<Q",f.read(8))[0]
        names.append(name)
print("n_layer", kvs.get("qwen35moe.block_count") or kvs.get("general.block_count") or kvs.get("llama.block_count"))
print("arch", kvs.get("general.architecture"))
print("full_attn_interval", {k:v for k,v in kvs.items() if "interval" in k.lower() or "full_attn" in k.lower()})
b40=[n for n in names if n.startswith("blk.40.")]
print("blk.40 count", len(b40))
for n in sorted(b40): print(n)
print("has ssm_conv1d", any("ssm_conv1d" in n for n in b40))
print("has attn_q", any(n.endswith("attn_q.weight") for n in b40))
