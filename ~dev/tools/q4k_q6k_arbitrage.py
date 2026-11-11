# q4k_q6k_arbitrage.py -- arbitrate the reference decoders against the
# authoritative gguf-package dequantizers for the REAL tensors of
# qwen2.5-coder_1.5b-base.gguf (general.quantization_version = 2).
import struct
import numpy as np
import gguf

MODEL = r"F:\rawrxd\models\qwen2.5-coder_1.5b-base.gguf"
TYPE_Q4_K, TYPE_Q6_K, TYPE_F32 = 12, 14, 0
BLOCK_VALS = 256
KMASK1, KMASK2, KMASK3 = 0x3F3F3F3F, 0x0F0F0F0F, 0x03030303


# --- verbatim copies of ref_multitoken_tied.py decoders -------------------
def dequant_q4_k_vec(src):
    nb = src.shape[0]
    d = src[:, 0:2].copy().view(np.float16).astype(np.float32)
    dmin = src[:, 2:4].copy().view(np.float16).astype(np.float32)
    utmp = np.zeros((nb, 4), dtype=np.uint32)
    utmp[:, 0:3] = src[:, 4:16].copy().view(np.uint32)
    utmp[:, 3] = ((utmp[:, 2] >> 4) & KMASK2) | (((utmp[:, 1] >> 6) & KMASK3) << 4)
    uaux = utmp[:, 1] & KMASK1
    utmp[:, 1] = (utmp[:, 2] & KMASK2) | (((utmp[:, 0] >> 6) & KMASK3) << 4)
    utmp[:, 2] = uaux
    utmp[:, 0] &= KMASK1
    packed = utmp.view(np.uint8)
    sc = packed[:, 0:8].astype(np.float32)
    mn = packed[:, 8:16].astype(np.float32)
    qs = src[:, 16:144]
    out = np.empty((nb, BLOCK_VALS), dtype=np.float32)
    for g in range(4):
        j = g * 64
        is_ = g * 2
        q = qs[:, g * 32:(g + 1) * 32]
        lo = (q & 0x0F).astype(np.float32)
        hi = (q >> 4).astype(np.float32)
        out[:, j:j + 32] = d * sc[:, is_:is_ + 1] * lo - dmin * mn[:, is_:is_ + 1]
        out[:, j + 32:j + 64] = d * sc[:, is_ + 1:is_ + 2] * hi \
            - dmin * mn[:, is_ + 1:is_ + 2]
    return out.reshape(-1)


def dequant_q6_k_vec(src):
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


# --- GGUF plumbing (same as the reference) --------------------------------
def read_header_kv(path):
    meta = {}
    with open(path, "rb") as fh:
        magic, version, tcount, kvcount = struct.unpack("<4sIQQ", fh.read(24))
        assert magic == b"GGUF"
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
                    fmtc = {0:("B",1),1:("b",1),2:("H",2),3:("h",2),
                            4:("I",4),5:("i",4),6:("f",4),7:("?",1),
                            10:("Q",8),11:("q",8),12:("d",8)}
                    c, esz = fmtc[etype]
                    val = list(struct.unpack(f"<{count}{c}", fh.read(esz * count)))
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
print(f"general.alignment={alignment} "
      f"general.quantization_version={meta.get('general.quantization_version')}")

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
print(f"data_start={data_start} tensors={len(tinfo)}")

reader = gguf.GGUFReader(MODEL)
pkg_off = {t.name: int(t.data_offset) for t in reader.tensors}
mismatch = [n for n in tinfo if n in pkg_off
            and data_start + tinfo[n][2] != pkg_off[n]]
print(f"OFFSET_MISMATCH_COUNT={len(mismatch)} {mismatch[:5]}")

BLOCK_BYTES = {TYPE_Q4_K: 144, TYPE_Q6_K: 210, TYPE_F32: 4}


def read_raw(name):
    dims, ttype, toff = tinfo[name]
    nvals = int(np.prod(dims))
    if ttype in (TYPE_Q4_K, TYPE_Q6_K):
        nb = (nvals + BLOCK_VALS - 1) // BLOCK_VALS
        nbytes = nb * BLOCK_BYTES[ttype]
    elif ttype == TYPE_F32:
        nbytes = nvals * 4
    else:
        raise RuntimeError(f"{name}: unsupported type {ttype}")
    f.seek(data_start + toff)
    return f.read(nbytes), dims, ttype


def deq_mat(name):
    raw, dims, ttype = read_raw(name)
    if ttype == TYPE_Q4_K:
        v = dequant_q4_k_vec(np.frombuffer(raw, dtype=np.uint8)
                             .reshape(-1, BLOCK_BYTES[TYPE_Q4_K]))
    elif ttype == TYPE_Q6_K:
        v = dequant_q6_k_vec(np.frombuffer(raw, dtype=np.uint8)
                             .reshape(-1, BLOCK_BYTES[TYPE_Q6_K]))
    else:
        v = np.frombuffer(raw, dtype=np.uint8).view(np.float32)
    cols = dims[0]
    rows = int(np.prod(dims[1:])) if len(dims) > 1 else 1
    if rows == 1 and cols == len(v):
        return v.astype(np.float32)
    return v.reshape(rows, cols).astype(np.float32)


def pkg_deq(name, limit=None):
    t = next(t for t in reader.tensors if t.name == name)
    qtype = t.tensor_type
    shape = [int(x) for x in t.shape]
    nrows = int(np.prod(shape[1:]))
    if limit is not None:
        nrows = min(nrows, limit)
    blk_vals, blk_sz = gguf.GGML_QUANT_SIZES[qtype]
    nb_per_row = (shape[0] + blk_vals - 1) // blk_vals
    row_bytes = nb_per_row * blk_sz
    with open(MODEL, "rb") as fh:
        fh.seek(int(t.data_offset))
        raw = fh.read(nrows * row_bytes)
    blk = np.frombuffer(raw, np.uint8).reshape(nrows * nb_per_row, blk_sz)
    v = np.asarray(gguf.quants.dequantize(blk, qtype), dtype=np.float32)
    return v.reshape(nrows, shape[0])


print("\n=== decoder arbitrage on real tensors (rows 0..255) ===")
for nm in ("blk.0.attn_q.weight", "blk.0.attn_k.weight", "blk.0.attn_v.weight",
           "blk.0.attn_output.weight", "blk.0.ffn_gate.weight",
           "blk.0.ffn_up.weight", "blk.0.ffn_down.weight",
           "blk.1.attn_q.weight", "blk.27.ffn_down.weight",
           "output_norm.weight", "token_embd.weight"):
    if nm not in tinfo:
        print(f"{nm}: MISSING")
        continue
    ttype = tinfo[nm][1]
    if ttype == TYPE_F32:
        a = deq_mat(nm)
        b = next(t for t in reader.tensors if t.name == nm).data[:]
        b = np.asarray(b, dtype=np.float32).reshape(-1)
        ok = np.allclose(a[:len(b)], b, rtol=0, atol=0)
        print(f"{nm:26s} F32   exact={ok} n={a.size}")
        continue
    limit = 256
    a = deq_mat(nm)[:limit]
    b = pkg_deq(nm, limit=limit)
    if a.shape != b.shape:
        print(f"{nm:26s} SHAPE MISMATCH ref={a.shape} pkg={b.shape}")
        continue
    diff = np.abs(a.astype(np.float64) - b.astype(np.float64))
    denom = max(float(np.abs(b.astype(np.float64)).max()), 1e-30)
    print(f"{nm:26s} {tinfo[nm][1]:>2}  maxabs={diff.max():.6g} "
          f"relmax={diff.max()/denom:.3g} ref_L2={np.sqrt((a.astype(np.float64)**2).sum()):.6g} "
          f"pkg_L2={np.sqrt((b.astype(np.float64)**2).sum()):.6g}")

print("\n=== bias tensors present ===")
for nm in sorted(n for n in tinfo if ".bias" in n):
    print(f"  {nm:34s} {tinfo[nm][0]} type={tinfo[nm][1]}")

print("\n=== vocab size check ===")
toks = reader.fields["tokenizer.ggml.tokens"]
print(f"tokenizer.ggml.tokens count = "
      f"{len(toks.parts[toks.data[0]])}")
print(f"token_embd dims = {tinfo['token_embd.weight'][0]}")
