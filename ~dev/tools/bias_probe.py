# bias_probe.py -- are the attn_q/k/v biases in this GGUF actually non-zero?
# llama.cpp's LLM_ARCH_QWEN2 path does NOT load .bias tensors, so non-zero
# biases make any reference that adds them diverge from llama.cpp.
import struct
import numpy as np

MODEL = r"F:\rawrxd\models\qwen2.5-coder_1.5b-base.gguf"
TYPE_Q4_K, TYPE_Q6_K, TYPE_F32 = 12, 14, 0
BLOCK_VALS = 256


def read_header_kv(path):
    meta = {}
    with open(path, "rb") as fh:
        magic, version, tcount, kvcount = struct.unpack("<4sIQQ", fh.read(24))
        for _ in range(kvcount):
            klen = struct.unpack("<Q", fh.read(8))[0]
            key = fh.read(klen).decode("utf-8", "replace")
            vtype = struct.unpack("<I", fh.read(4))[0]
            if vtype == 8:
                n = struct.unpack("<Q", fh.read(8))[0]
                val = fh.read(n).decode("utf-8", "replace")
            elif vtype == 9:
                etype = struct.unpack("<I", fh.read(4))[0]
                count = struct.unpack("<Q", fh.read(8))[0]
                if etype == 8:
                    val = []
                    for _ in range(count):
                        n = struct.unpack("<Q", fh.read(8))[0]
                        val.append(fh.read(n).decode("utf-8", "replace"))
                else:
                    fmtc = {0:("B",1),1:("b",1),2:("H",2),3:("h",2),4:("I",4),
                            5:("i",4),6:("f",4),7:("?",1),10:("Q",8),11:("q",8),
                            12:("d",8)}
                    c, esz = fmtc[etype]
                    val = list(struct.unpack(f"<{count}{c}", fh.read(esz*count)))
            else:
                fmtc = {0:("B",1),1:("b",1),2:("H",2),3:("h",2),4:("I",4),
                        5:("i",4),6:("f",4),7:("?",1),10:("Q",8),11:("q",8),
                        12:("d",8)}
                c, esz = fmtc[vtype]
                val = struct.unpack(f"<{c}", fh.read(esz))[0]
            meta[key] = val
        hdr_end = fh.tell()
    return meta, tcount, hdr_end


meta, tcount, hdr_end = read_header_kv(MODEL)
alignment = int(meta.get("general.alignment", 32))
f = open(MODEL, "rb")
f.seek(hdr_end)
tinfo = {}
for _ in range(tcount):
    nlen = struct.unpack("<Q", f.read(8))[0]
    name = f.read(nlen).decode("utf-8", "replace")
    ndims = struct.unpack("<I", f.read(4))[0]
    dims = [struct.unpack("<Q", f.read(8))[0] for _ in range(ndims)]
    ttype = struct.unpack("<I", f.read(4))[0]
    toff = struct.unpack("<Q", f.read(8))[0]
    tinfo[name] = (dims, ttype, toff)
dir_end = f.tell()
data_start = (dir_end + alignment - 1) // alignment * alignment

print("=== attention bias tensors ===")
tot_nz = 0
for nm in sorted(n for n in tinfo if n.endswith((".attn_q.bias", ".attn_k.bias", ".attn_v.bias"))):
    dims, tt, toff = tinfo[nm]
    nvals = int(np.prod(dims))
    f.seek(data_start + toff)
    v = np.frombuffer(f.read(nvals * 4), dtype=np.float32)
    nz = int(np.count_nonzero(v))
    tot_nz += nz
    if nm.startswith(("blk.0.", "blk.14.", "blk.27.")):
        print(f"{nm:26s} n={v.size} min={v.min():+.6g} max={v.max():+.6g} "
              f"L2={np.sqrt((v.astype(np.float64)**2).sum()):.6g} nonzero={nz}")
print(f"TOTAL_NONZERO_BIAS_VALUES={tot_nz}")
print(f"BIAS_IS_ZERO={tot_nz == 0}")
