# q6k_layout_audit.py -- decisive Q6_K layout arbitrage.
#
# The reference implementation (ref_multitoken_tied.py) decodes Q6_K with the
# *legacy* K-quant layout while embedding rows for the same GGUF decode to
# L2=0.744 with the *interleaved* layout.  This script settles the question
# with three independent decoders and an offset cross-check:
#
#   1. gguf.quants.dequantize        (authoritative, llama.cpp-maintained)
#   2. interleaved layout (audit/ggml current)
#   3. legacy layout (ref_multitoken_tied.py)
#
# It also cross-checks the reference's own data_start + toff arithmetic
# against the GGUFReader's absolute tensor offsets.
import struct
import numpy as np
import gguf
from gguf.quants import dequantize as gguf_dequant

MODEL = r"F:\rawrxd\models\qwen2.5-coder_1.5b-base.gguf"
H = 1536
TOK = 750
BLOCK_VALS = 256

# ---------------------------------------------------------------------------
print("=== header / tensor table (authoritative) ===")
reader = gguf.GGUFReader(MODEL)


def fval(key):
    f = reader.fields[key]
    return np.asarray(f.parts[f.data[0]]).reshape(-1)[0]


print(f"embedding_length = {fval('qwen2.embedding_length')}")
print(f"general.alignment  = "
      f"{reader.fields['general.alignment'].contents() if 'general.alignment' in reader.fields else 32}")
print(f"general.quantization_version = {fval('general.quantization_version')}")
print(f"qwen2.vocab (n_ctx tokens via tokenizer.ggml.tokens length) = "
      f"{len([k for k in reader.fields if 'tokenizer.ggml.tokens' == k])}")

tinfo = {}
for t in reader.tensors:
    tinfo[t.name] = (list(t.shape), t.tensor_type.name, int(t.data_offset))

em = next(t for t in reader.tensors if t.name == "token_embd.weight")
print(f"token_embd.weight shape={list(em.shape)} type={em.tensor_type.name} "
      f"count={int(np.prod(em.shape))} abs_offset={int(em.data_offset)}")

for nm in ("blk.0.attn_q.weight", "blk.0.attn_k.weight", "blk.0.attn_v.weight",
           "blk.0.attn_output.weight", "blk.0.ffn_gate.weight",
           "blk.0.ffn_down.weight", "blk.0.attn_q.bias",
           "output_norm.weight", "token_embd.weight"):
    print(f"  {nm:28s} shape={str(tinfo[nm][0]):16s} type={tinfo[nm][1]} "
          f"abs_off={tinfo[nm][2]}")

# ---------------------------------------------------------------------------
# Reference-script arithmetic (mirrors ref_multitoken_tied.py exactly).
print("\n=== reference offset arithmetic cross-check ===")
with open(MODEL, "rb") as fh:
    magic, version, tcount, kvcount = struct.unpack("<4sIQQ", fh.read(24))
    for _ in range(kvcount):
        klen = struct.unpack("<Q", fh.read(8))[0]
        key = fh.read(klen).decode("utf-8", "replace")
        vtype = struct.unpack("<I", fh.read(4))[0]
        if vtype == 8:
            n = struct.unpack("<Q", fh.read(8))[0]
            fh.read(n)
        elif vtype == 9:
            etype = struct.unpack("<I", fh.read(4))[0]
            count = struct.unpack("<Q", fh.read(8))[0]
            if etype == 8:
                for _ in range(count):
                    n = struct.unpack("<Q", fh.read(8))[0]
                    fh.read(n)
            else:
                fmtc = {0:("B",1),1:("b",1),2:("H",2),3:("h",2),4:("I",4),
                        5:("i",4),6:("f",4),7:("?",1),10:("Q",8),11:("q",8),
                        12:("d",8)}
                c, esz = fmtc[etype]
                fh.read(esz * count)
        else:
            fmtc = {0:("B",1),1:("b",1),2:("H",2),3:("h",2),4:("I",4),
                    5:("i",4),6:("f",4),7:("?",1),10:("Q",8),11:("q",8),
                    12:("d",8)}
            c, esz = fmtc[vtype]
            fh.read(esz)
    hdr_end = fh.tell()

    fh.seek(hdr_end)
    reftinfo = {}
    for _ in range(tcount):
        nlen = struct.unpack("<Q", fh.read(8))[0]
        name = fh.read(nlen).decode("utf-8", "replace")
        ndims = struct.unpack("<I", fh.read(4))[0]
        dims = [struct.unpack("<Q", fh.read(8))[0] for _ in range(ndims)]
        ttype = struct.unpack("<I", fh.read(4))[0]
        toff = struct.unpack("<Q", fh.read(8))[0]
        reftinfo[name] = (dims, ttype, toff)
    dir_end = fh.tell()
    alignment = 32
    data_start = (dir_end + alignment - 1) // alignment * alignment
    print(f"hdr_end={hdr_end} dir_end={dir_end} data_start={data_start}")
    abs_ref = data_start + reftinfo["token_embd.weight"][2]
    abs_pkg = int(em.data_offset)
    print(f"token_embd abs offset  ref_math={abs_ref}  gguf_pkg={abs_pkg}  "
          f"delta={abs_ref - abs_pkg}")
    print(f"ref token_embd dims={reftinfo['token_embd.weight'][0]} "
          f"ggml_type_id={reftinfo['token_embd.weight'][1]} (12=Q4_K, 14=Q6_K)")

# ---------------------------------------------------------------------------
print("\n=== decoder arbitrage: token_embd row 750 ===")
nb_per_row = (H + BLOCK_VALS - 1) // BLOCK_VALS
row_bytes = nb_per_row * 210
abs_row = int(em.data_offset) + TOK * row_bytes
with open(MODEL, "rb") as fh:
    fh.seek(abs_row)
    raw = fh.read(row_bytes)
print(f"row bytes={row_bytes} abs_off={abs_row} sha256=" +
      f"{__import__('hashlib').sha256(raw).hexdigest()}")

blk = np.frombuffer(raw, dtype=np.uint8).reshape(nb_per_row, 210)

# decoder 1: gguf package (authoritative, llama.cpp-maintained)
v1 = np.asarray(gguf.quants.dequantize(blk, gguf.GGMLQuantizationType.Q6_K),
                dtype=np.float32).reshape(-1)[:H]


def decode_interleaved(src):
    nb = src.shape[0]
    ql = src[:, 0:128].astype(np.uint32)
    qh = src[:, 128:192].astype(np.uint32)
    sc = src[:, 192:208].copy().view(np.int8).astype(np.float64)
    d = src[:, 208:210].copy().view(np.float16).astype(np.float64)
    idx = np.arange(BLOCK_VALS)
    nib_lo = ql[:, idx >> 1] & 0x0F
    nib_hi = (ql[:, idx >> 1] >> 4) & 0x0F
    lane = idx & 1
    q_lo = np.where(lane[None, :] == 0, nib_lo, nib_hi)
    byte = qh[:, idx >> 2]
    q_hi = (byte >> ((idx % 4) * 2)) & 0x03
    q = (q_lo | (q_hi << 4)).astype(np.float64) - 32.0
    return (q * np.repeat(sc, 16, axis=1) * d).reshape(-1)


def decode_legacy(src):
    nb = src.shape[0]
    ql = src[:, 0:128]
    qh = src[:, 128:192]
    scales = src[:, 192:208].copy().view(np.int8).astype(np.float32)
    d = src[:, 208:210].copy().view(np.float16).astype(np.float32)
    w = np.empty((nb, BLOCK_VALS), dtype=np.int32)
    for jj in range(2):
        q4 = ql[:, jj * 64:(jj + 1) * 64]
        q2 = qh[:, jj * 32:(jj + 1) * 32]
        base = jj * 128
        w[:, base + 0:base + 32] = ((q4[:, 0:32] & 0xF)
            | (((q2 >> 0) & 3) << 4)).astype(np.int32) - 32
        w[:, base + 32:base + 64] = ((q4[:, 32:64] & 0xF)
            | (((q2 >> 2) & 3) << 4)).astype(np.int32) - 32
        w[:, base + 64:base + 96] = ((q4[:, 0:32] >> 4)
            | (((q2 >> 4) & 3) << 4)).astype(np.int32) - 32
        w[:, base + 96:base + 128] = ((q4[:, 32:64] >> 4)
            | (((q2 >> 6) & 3) << 4)).astype(np.int32) - 32
    dexp = np.repeat(d * scales, 16, axis=1)
    return (dexp * w).reshape(-1)


v2 = decode_interleaved(blk)[:H]
v3 = decode_legacy(blk)[:H]

for name, v in (("gguf_pkg", v1), ("interleaved", v2), ("legacy", v3)):
    if v is None:
        print(f"{name:12s} <unavailable>")
        continue
    print(f"{name:12s} FIRST8={','.join(f'{x:.9g}' for x in np.asarray(v[:8]))}")
    print(f"{'':12s} MIN={float(np.min(v)):.9g} MAX={float(np.max(v)):.9g} "
          f"L2={float(np.sqrt(np.sum(np.asarray(v, dtype=np.float64) ** 2))):.9g}")

# ---------------------------------------------------------------------------
print("\n=== lm-head / tied-embedding geometry ===")
for nm in ("output.weight", "token_embd.weight"):
    if nm in tinfo:
        print(f"  {nm} shape={tinfo[nm][0]} type={tinfo[nm][1]}")
print("output.weight present:", "output.weight" in tinfo)

# ---------------------------------------------------------------------------
print("\n=== q4_k cross-check on the same row (layout mismatch detector) ===")
v4 = None
try:
    nb4 = (H + 255) // 256
    row_bytes4 = nb4 * 144
    with open(MODEL, "rb") as fh:
        fh.seek(int(em.data_offset) + TOK * row_bytes4)
        raw4 = fh.read(row_bytes4)
    v4 = np.asarray(
        gguf.quants.dequantize(np.frombuffer(raw4, np.uint8).reshape(nb4, 144),
                               gguf.GGMLQuantizationType.Q4_K),
        np.float32).reshape(-1)[:H]
    print(f"q4_k read  FIRST8={','.join(f'{x:.9g}' for x in v4[:8])}")
    print(f"q4_k read  MIN={float(v4.min()):.9g} MAX={float(v4.max()):.9g} "
          f"L2={float(np.sqrt(np.sum(v4.astype(np.float64) ** 2))):.9g}")
except Exception as e:
    print("q4_k check skipped:", e)
