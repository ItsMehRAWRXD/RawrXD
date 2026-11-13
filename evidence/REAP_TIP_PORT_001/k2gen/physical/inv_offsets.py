import struct, os, glob, json
root = r"F:\ollamamodels\Kimi-K2-Instruct-0905-GGUF\Q4_K_M"
files = sorted(glob.glob(os.path.join(root, "Kimi-K2-Instruct-0905-Q4_K_M-*-of-00013.gguf")))

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

def classify(name):
    if any(k in name for k in ("ffn_gate_exps","ffn_up_exps","ffn_down_exps")):
        return "routed_exps"
    if "ffn_gate_inp" in name or "exp_probs_b" in name:
        return "router"
    if "shexp" in name:
        return "shared_exp"
    if any(k in name for k in ("ffn_gate.","ffn_up.","ffn_down.")):
        return "dense_ffn"
    return "shared_other"

totals = {k:0 for k in ("routed_exps","router","shared_exp","dense_ffn","shared_other")}
disk=0; layers=set(); ecount=None; n_tensors=0
for path in files:
    fsz=os.path.getsize(path); disk+=fsz
    with open(path,"rb") as f:
        magic, ver = struct.unpack("<II", f.read(8))
        nt, nkv = struct.unpack("<QQ", f.read(16))
        for _ in range(nkv):
            read_str(f); t=struct.unpack("<I", f.read(4))[0]; skip_val(f,t)
        tensors=[]
        for _ in range(nt):
            name=read_str(f)
            nd=struct.unpack("<I", f.read(4))[0]
            dims=[struct.unpack("<Q", f.read(8))[0] for __ in range(nd)]
            typ=struct.unpack("<I", f.read(4))[0]
            off=struct.unpack("<Q", f.read(8))[0]
            tensors.append((name,dims,typ,off))
        # data_start: after alignment of current tell
        desc_end = f.tell()
        # GGUF alignment default 32
        align=32
        data_start = (desc_end + align - 1) // align * align
        # Exact tensor sizes from sorted offsets within data section
        by_off = sorted(tensors, key=lambda x: x[3])
        for i,(name,dims,typ,off) in enumerate(by_off):
            if i+1 < len(by_off):
                nbytes = by_off[i+1][3] - off
            else:
                nbytes = fsz - (data_start + off)
            if nbytes < 0: nbytes = 0
            kind=classify(name)
            totals[kind]+=nbytes
            n_tensors+=1
            if kind=="routed_exps":
                if name.startswith("blk."):
                    try: layers.add(int(name.split(".")[1]))
                    except: pass
                if ecount is None and dims: ecount=dims[-1]

shared = totals["router"]+totals["shared_exp"]+totals["dense_ffn"]+totals["shared_other"]
pruneable = totals["routed_exps"]
E = ecount or 384
L = len(layers) or 60
bytes_per_expert_all_layers = pruneable // E
budget = 19511390163  # tip WS from 30GB target
retained = max(8, (budget - shared) // bytes_per_expert_all_layers) if bytes_per_expert_all_layers else 8
retained = min(retained, E)
repacked = shared + bytes_per_expert_all_layers * retained
pruned = bytes_per_expert_all_layers * (E - retained)
out = {
  "method": "offset_diff_per_shard",
  "shards": len(files),
  "disk_bytes": disk,
  "tensor_count": n_tensors,
  "moe_layers": L,
  "expert_count": E,
  "bytes": totals,
  "SHARED_KEEP_BYTES": shared,
  "ROUTED_EXPERT_BYTES": pruneable,
  "BYTES_PER_EXPERT_ALL_LAYERS": bytes_per_expert_all_layers,
  "budget_ws_bytes": budget,
  "RETAINED_EXPERT_COUNT": retained,
  "REPACKED_MODEL_BYTES": repacked,
  "PRUNED_ROUTED_EXPERT_BYTES": pruned,
  "REPACKED_FRAC_OF_DISK": round(repacked/disk, 6),
  "NOTE": "REPACKED is shared_keep + retained routed experts only; not a claim of complete executable without MLA/embed accuracy check"
}
print(json.dumps(out, indent=2))
