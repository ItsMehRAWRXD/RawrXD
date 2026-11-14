# Offline O-proj isolate: blk.14.attn_output Q4_K GEMV vs dumps.
# PROMOTE=0 TIP_CLIMB=HOLD INVENT_PASS=0
import struct, math, os, sys

GGUF = r"G:\~dev\rawrxd\models\tinyllama.gguf"
STAGE = r"G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\FIRST_DIVERGE_001\_cmp_attn_out14_stage"
EV = r"G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\FIRST_DIVERGE_001"


def fp16_to_f32(h):
    s = (h >> 15) & 1
    e = (h >> 10) & 0x1F
    f = h & 0x3FF
    if e == 0:
        if f == 0:
            return -0.0 if s else 0.0
        # denorm
        return ((-1) ** s) * (2 ** -14) * (f / 1024.0)
    if e == 31:
        return float("nan") if f else (float("-inf") if s else float("inf"))
    return ((-1) ** s) * (2 ** (e - 15)) * (1.0 + f / 1024.0)


def unpack_q4k_scale_min(scales, j):
    if j < 4:
        return scales[j] & 63, scales[j + 4] & 63
    sc = (scales[j + 4] & 0x0F) | ((scales[j - 4] >> 6) << 4)
    m = (scales[j + 4] >> 4) | ((scales[j] >> 6) << 4)
    return sc, m


def dequant_q4k_block(blob):
    # 144 bytes: d(2) dmin(2) scales(12) qs(128)
    d = fp16_to_f32(struct.unpack_from("<H", blob, 0)[0])
    dmin = fp16_to_f32(struct.unpack_from("<H", blob, 2)[0])
    scales = blob[4:16]
    q = blob[16:144]
    out = [0.0] * 256
    y = 0
    qi = 0
    for is_ in range(0, 8, 2):
        sc0, m0 = unpack_q4k_scale_min(scales, is_)
        sc1, m1 = unpack_q4k_scale_min(scales, is_ + 1)
        d1, min1 = d * sc0, dmin * m0
        d2, min2 = d * sc1, dmin * m1
        for l in range(32):
            out[y + l] = d1 * (q[qi + l] & 0xF) - min1
        for l in range(32):
            out[y + 32 + l] = d2 * (q[qi + l] >> 4) - min2
        y += 64
        qi += 32
    return out


def load_f32(path):
    b = open(path, "rb").read()
    n = len(b) // 4
    return list(struct.unpack("<%df" % n, b))


def max_abs_diff(a, b):
    n = min(len(a), len(b))
    mx = 0.0
    fbi = None
    for i in range(n):
        d = abs(a[i] - b[i])
        if d > mx:
            mx = d
        if fbi is None and d > 1e-4:
            fbi = i
    return mx, fbi, n


def read_gguf_tensor(path, name):
    with open(path, "rb") as f:
        magic = f.read(4)
        assert magic == b"GGUF"
        ver = struct.unpack("<I", f.read(4))[0]
        n_tensors, n_kv = struct.unpack("<QQ", f.read(16))
        # skip KV
        for _ in range(n_kv):
            (klen,) = struct.unpack("<Q", f.read(8))
            f.read(klen)
            (typ,) = struct.unpack("<I", f.read(4))
            # value by type
            if typ == 8:  # string
                (n,) = struct.unpack("<Q", f.read(8))
                f.read(n)
            elif typ == 9:  # array
                (at,) = struct.unpack("<I", f.read(4))
                (n,) = struct.unpack("<Q", f.read(8))
                # element sizes
                sz = {0: 1, 1: 1, 2: 2, 3: 2, 4: 4, 5: 4, 6: 4, 7: 8, 10: 1, 11: 1, 12: 8}.get(at)
                if at == 8:
                    for __ in range(n):
                        (sl,) = struct.unpack("<Q", f.read(8))
                        f.read(sl)
                else:
                    if sz is None:
                        raise RuntimeError("unsupported array type %d" % at)
                    f.read(n * sz)
            else:
                sz = {0: 1, 1: 1, 2: 2, 3: 2, 4: 4, 5: 4, 6: 4, 7: 8, 10: 1, 11: 1, 12: 8}[typ]
                f.read(sz)
        # tensor infos
        infos = []
        for _ in range(n_tensors):
            (nlen,) = struct.unpack("<Q", f.read(8))
            tname = f.read(nlen).decode("utf-8")
            (ndims,) = struct.unpack("<I", f.read(4))
            dims = [struct.unpack("<Q", f.read(8))[0] for __ in range(ndims)]
            (wtype,) = struct.unpack("<I", f.read(4))
            (offset,) = struct.unpack("<Q", f.read(8))
            infos.append((tname, dims, wtype, offset))
        # align to data
        data_off = f.tell()
        # GGUF alignment 32
        align = 32
        data_off = (data_off + align - 1) // align * align
        for tname, dims, wtype, offset in infos:
            if tname != name:
                continue
            # dims in GGUF are [cols, rows] typically for 2D weights
            f.seek(data_off + offset)
            # Q4_K = type 12
            assert wtype == 12, "expected Q4_K type 12 got %d" % wtype
            cols, rows = dims[0], dims[1] if len(dims) > 1 else 1
            nblocks = (cols + 255) // 256
            nbytes = rows * nblocks * 144
            blob = f.read(nbytes)
            return rows, cols, blob
    raise KeyError(name)


def q4k_gemv(blob, rows, cols, x):
    nblocks = (cols + 255) // 256
    out = [0.0] * rows
    for r in range(rows):
        base = r * nblocks * 144
        s = 0.0
        for b in range(nblocks):
            blk = dequant_q4k_block(blob[base + b * 144 : base + (b + 1) * 144])
            off = b * 256
            n = min(256, cols - off)
            for i in range(n):
                s += blk[i] * x[off + i]
        out[r] = s
    return out


def main():
    rows, cols, blob = read_gguf_tensor(GGUF, "blk.14.attn_output.weight")
    print("wo rows=%d cols=%d bytes=%d" % (rows, cols, len(blob)))
    pre = load_f32(os.path.join(STAGE, "deep2_ATTN_PRE_O_14_pos0_layer0_full_n2048_seq264.bin"))
    deep_out = load_f32(os.path.join(STAGE, "deep2_ATTN_OUT_14_pos0_layer0_full_n2048_seq265.bin"))
    llama_out = load_f32(os.path.join(STAGE, "llama_ATTN_OUT_14.bin"))
    assert len(pre) == cols, (len(pre), cols)
    pred = q4k_gemv(blob, rows, cols, pre)
    mx_d, fbi_d, _ = max_abs_diff(pred, deep_out)
    mx_l, fbi_l, _ = max_abs_diff(pred, llama_out)
    mx_dl, fbi_dl, _ = max_abs_diff(deep_out, llama_out)
    print("offline(pre_deep2) vs deep2_ATTN_OUT maxAbs=%.6e first_bad=%s" % (mx_d, fbi_d))
    print("offline(pre_deep2) vs llama_ATTN_OUT maxAbs=%.6e first_bad=%s" % (mx_l, fbi_l))
    print("deep2_ATTN_OUT vs llama_ATTN_OUT maxAbs=%.6e first_bad=%s" % (mx_dl, fbi_dl))
    # residual
    l13 = load_f32(os.path.join(STAGE, "deep2_LAYER13_OUT_pos0_layer0_full_n2048_seq255.bin"))
    fi = load_f32(os.path.join(STAGE, "deep2_FFN_INP_14_pos0_layer0_full_n2048_seq266.bin"))
    mx_r = max(abs(fi[i] - (deep_out[i] + l13[i])) for i in range(2048))
    print("deep2 residual FFN_INP-(ATTN_OUT+L13) maxAbs=%.6e" % mx_r)
    # FINAL
    fin = load_f32(os.path.join(STAGE, "deep2_FINAL_NORM_pos0_layer0_full_n2048_seq402.bin"))
    ref = load_f32(os.path.join(STAGE, "llama_REF_FINAL_HIDDEN_pos0.bin"))
    mx_f, fbi_f, _ = max_abs_diff(fin, ref)
    print("FINAL_NORM vs REF maxAbs=%.6e first_bad=%s FUNCTIONAL_FAIL=%d" % (mx_f, fbi_f, 1 if mx_f > 1e-4 else 0))
    # verdict
    if mx_d < 1e-4:
        print("VERDICT=O_PROJ_SELF_CONSISTENT_HOST_Q4K (deep2 OUT matches offline GEMV of dumped PRE_O)")
        if mx_dl > 1e-4:
            print("NEXT=O_PROJ_INPUT_OR_UPSTREAM (OUT gap vs llama not from host Q4K kernel vs dumped PRE_O)")
            print("TRUE_LOCAL_SITE=ATTN_OUT_14_via_O_PROJ_OF_PRE_O_RESIDUAL_OR_REF_PRE_O_GAP")
    else:
        print("VERDICT=O_PROJ_KERNEL_OR_WEIGHT_MISMATCH vs deep2 dump")
    print("PROMOTE=0 TIP_CLIMB=HOLD")


if __name__ == "__main__":
    main()
