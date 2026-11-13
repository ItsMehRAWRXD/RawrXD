import struct, json, glob, os
from pathlib import Path

root = Path(r"F:\ollamamodels\MiniMax-M2.7-Q4_K_M\MiniMax-M2.7-Q4_K_M")
shards = sorted(root.glob("MiniMax-M2.7-Q4_K_M-*-of-*.gguf"))

def read_str(f):
    n = struct.unpack("<Q", f.read(8))[0]
    return f.read(n).decode("utf-8", "replace")

def skip_val(f, t):
    sizes = {0:1,1:1,2:2,3:2,4:4,5:4,6:4,7:1,10:8,11:8,12:8}
    if t == 8:
        read_str(f); return
    if t == 9:
        et = struct.unpack("<I", f.read(4))[0]
        n = struct.unpack("<Q", f.read(8))[0]
        for _ in range(n): skip_val(f, et)
        return
    f.read(sizes[t])

def list_tensors(path):
    out = []
    with open(path, "rb") as f:
        magic, ver = struct.unpack("<II", f.read(8))
        nt, nkv = struct.unpack("<QQ", f.read(16))
        for _ in range(nkv):
            k = read_str(f)
            t = struct.unpack("<I", f.read(4))[0]
            skip_val(f, t)
        data_start = None
        # after KV, tensor infos; dataOffset typically after all infos padded
        for i in range(nt):
            n = read_str(f)
            nd = struct.unpack("<I", f.read(4))[0]
            dims = [struct.unpack("<Q", f.read(8))[0] for _ in range(nd)]
            typ = struct.unpack("<I", f.read(4))[0]
            off = struct.unpack("<Q", f.read(8))[0]
            out.append({"name": n, "dims": dims, "type": typ, "rel_off": off})
    return out

layers_of_interest = {0, 1, 3, 31, 61}
rec = {"shards": [], "by_layer": {}}
for si, sp in enumerate(shards):
    tens = list_tensors(sp)
    srec = {"shard": si, "path": str(sp), "tensor_count": len(tens), "attn_ffn_sample": []}
    for t in tens:
        name = t["name"]
        # layer parse
        li = None
        if name.startswith("blk."):
            try:
                li = int(name.split(".")[1])
            except Exception:
                li = None
        keep = False
        if li in layers_of_interest and any(x in name for x in ("attn", "ffn", "norm", "exp_probs")):
            keep = True
        if name in ("token_embd.weight", "output.weight", "output_norm.weight"):
            keep = True
        if keep:
            item = {**t, "shard": si}
            srec["attn_ffn_sample"].append(item)
            key = str(li) if li is not None else "root"
            rec["by_layer"].setdefault(key, []).append(item)
    rec["shards"].append({"shard": si, "path": str(sp), "tensor_count": len(tens)})
    print(f"shard{si} tensors={len(tens)} kept={len(srec['attn_ffn_sample'])}")

# summarize L0 attn layout
print("--- L0 ---")
for t in sorted(rec["by_layer"].get("0", []), key=lambda x: x["name"]):
    print(f"  shard{t['shard']} {t['name']} dims={t['dims']} type={t['type']}")

outp = Path(r"g:\~dev\rawrxd\evidence\REAP_MULTI_MODEL_001\B03_TOPOLOGY\L0_TENSOR_INVENTORY.json")
outp.write_text(json.dumps(rec, indent=2), encoding="utf-8")
print("wrote", outp)
