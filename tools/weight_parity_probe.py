#!/usr/bin/env python3
"""Isolate weight-level vs math-level divergence.

Recomputes the layer-0 Q / (kv_a) / (kv_b V) / wo projections in double
precision directly from the GGUF tensor bytes (ggml-exact Q4_K dequant),
using the captured native inputs (which match the reference to 1e-6), then
compares against both the native records and the reference PACT dumps.
"""
import struct
import sys

import numpy as np

GGUF = r"F:\rawrxd\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf"
EV = r"F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001"
REF = r"F:\rawrxd\evidence\NUGVERSE_ESTIMATOR_001"


def parse_gguf_tables(path):
    with open(path, "rb") as f:
        head = f.read(24)
        magic, version = struct.unpack_from("<4sI", head, 0)
        n_tensors, n_kv = struct.unpack_from("<QQ", head, 8)
        assert magic == b"GGUF" and version == 3, (magic, version)
        pos = 24
        kv = {}

        def rd_str(f, pos):
            f.seek(pos)
            (n,) = struct.unpack("<Q", f.read(8))
            s = f.read(n).decode("utf-8", "replace")
            return s, pos + 8 + n

        def skip_val(f, pos, t, depth=0):
            sizes = {0: 1, 1: 1, 2: 2, 3: 2, 4: 4, 5: 4, 6: 4, 7: 1,
                     10: 8, 11: 8, 12: 8}
            if t in sizes:
                return pos + sizes[t]
            if t == 8:
                s, pos = rd_str(f, pos)
                return pos
            if t == 9:
                f.seek(pos)
                (et,) = struct.unpack("<I", f.read(4))
                (cn,) = struct.unpack("<Q", f.read(8))
                p2 = pos + 12
                if et == 8:
                    for _ in range(cn):
                        _, p2 = rd_str(f, p2)
                    return p2
                esz = {0: 1, 1: 1, 2: 2, 3: 2, 4: 4, 5: 4, 6: 4, 7: 1,
                       10: 8, 11: 8, 12: 8}[et]
                return p2 + cn * esz
            raise ValueError("bad type %d" % t)

        f.seek(0)
        for _ in range(n_kv):
            key, pos = rd_str(f, pos)
            f.seek(pos)
            (t,) = struct.unpack("<I", f.read(4))
            pos += 4
            if t == 8:
                v, pos = rd_str(f, pos)
                kv[key] = v
            elif t == 9:
                f.seek(pos)
                (et,) = struct.unpack("<I", f.read(4))
                (cn,) = struct.unpack("<Q", f.read(8))
                if et == 4:
                    f.seek(pos + 12)
                    kv[key] = struct.unpack("<%dI" % cn, f.read(4 * cn))
                else:
                    pos = skip_val(f, pos, t)
            else:
                sizes = {0: 1, 1: 1, 2: 2, 3: 2, 4: 4, 5: 4, 6: 4, 7: 1,
                         10: 8, 11: 8, 12: 8}
                if t in sizes:
                    f.seek(pos)
                    raw = f.read(sizes[t])
                    if t == 4:
                        kv[key] = struct.unpack("<I", raw)[0]
                    elif t == 6:
                        kv[key] = struct.unpack("<f", raw)[0]
                    elif t == 5:
                        kv[key] = struct.unpack("<i", raw)[0]
                    pos += sizes[t]
                else:
                    raise ValueError("unhandled kv type %d for %s" % (t, key))

        tensors = {}
        for _ in range(n_tensors):
            name, pos = rd_str(f, pos)
            f.seek(pos)
            (nd,) = struct.unpack("<I", f.read(4))
            pos += 4
            f.seek(pos); dims = struct.unpack("<%dQ" % nd, f.read(8 * nd))
            pos += 8 * nd
            f.seek(pos)
            (t,) = struct.unpack("<I", f.read(4))
            pos += 4
            f.seek(pos)
            (off,) = struct.unpack("<Q", f.read(8))
            pos += 8
            tensors[name] = {"dims": dims, "type": t, "offset": off}
        return kv, tensors, pos


def dequant_q4_k(buf, n):
    out = np.zeros(n, dtype=np.float64)
    for b in range(n // 256):
        blk = np.frombuffer(buf, dtype=np.uint8, count=144, offset=b * 144)
        d = np.frombuffer(blk[0:2].tobytes(), dtype=np.float16)[0].astype(np.float64)
        dmin = np.frombuffer(blk[2:4].tobytes(), dtype=np.float16)[0].astype(np.float64)
        sc = blk[4:16]
        qs = blk[16:144]

        def sm(j):
            if j < 4:
                return int(sc[j] & 63), int(sc[j + 4] & 63)
            d_s = (int(sc[j + 4] & 0x0F) | ((int(sc[j - 4]) >> 6) << 4))
            m_s = ((int(sc[j + 4]) >> 4) | ((int(sc[j]) >> 6) << 4))
            return d_s, m_s

        is_ = 0
        for j in range(0, 256, 64):
            s0, m0 = sm(is_)
            s1, m1 = sm(is_ + 1)
            d1, mn1 = d * s0, dmin * m0
            d2, mn2 = d * s1, dmin * m1
            base = b * 256 + j
            q = qs[(j // 64) * 32:(j // 64) * 32 + 32].astype(np.int32)
            out[base:base + 32] = d1 * (q & 0xF) - mn1
            out[base + 32:base + 64] = d2 * (q >> 4) - mn2
            is_ += 2
    return out


def rd_nat(p):
    d = open(p, "rb").read()
    op, layer = struct.unpack_from("<II", d, 0)
    pos = struct.unpack_from("<Q", d, 8)[0]
    (nd,) = struct.unpack_from("<I", d, 16)
    off = 20
    cnt = struct.unpack_from("<Q", d, off + 8 * nd)[0]
    off += 8 * nd + 8
    return {"op": op, "layer": layer, "pos": pos,
            "v": np.frombuffer(d[off:off + cnt * 4], dtype=np.float32).astype(np.float64)}


def rd_ref(p):
    d = open(p, "rb").read()
    (magic,) = struct.unpack_from("<I", d, 0)
    assert magic == 0x54434150
    (layer,) = struct.unpack_from("<Q", d, 8)
    (nlen,) = struct.unpack_from("<I", d, 16)
    name = d[20:20 + nlen].decode()
    off = 20 + nlen
    (nd,) = struct.unpack_from("<I", d, off)
    off += 4
    off += 8 * nd
    return {"layer": layer, "name": name,
            "v": np.frombuffer(d[off:], dtype=np.float32).astype(np.float64)}


def main():
    pos = 0
    nat_dir = r"F:\rawrxd\evidence\NUGVERSE_ESTIMATOR_001\differential_pos0_token1"
    kv, tensors, table_end = parse_gguf_tables(GGUF)
    align = int(kv.get("general.alignment", 32))
    data_start = (table_end + align - 1) // align * align
    print("tensors parsed: %d  data_start=%d" % (len(tensors), data_start))

    def get_dequant(name):
        t = tensors[name]
        raw = open(GGUF, "rb")
        raw.seek(data_start + t["offset"])
        n = 1
        for d in t["dims"]:
            n *= d
        buf = raw.read((n // 256) * 144 if t["type"] == 12 else n * 4)
        assert len(buf) > 0, name
        if t["type"] == 12:
            w = dequant_q4_k(buf, n).reshape(t["dims"][0], t["dims"][1], order="F")
        else:
            w = np.frombuffer(buf, dtype=np.float32, count=n).astype(np.float64).reshape(
                t["dims"][0], t["dims"][1], order="F")
        return w

    import glob
    import os
    recs = {}
    for p in glob.glob(os.path.join(nat_dir, "*.bin")):
        d = open(p, "rb").read()
        (op,) = struct.unpack_from("<I", d, 0)
        (pos_,) = struct.unpack_from("<Q", d, 8, )
        recs.setdefault((op, pos_), []).append(p)
    # op1 = attn rmsnorm output (layer 0)
    op1 = rd_nat([p for (op, _), ps in recs.items() if op == 1 for p in ps][0])["v"]
    print("op1(rmsnorm) n=%d range=[%.4f, %.4f]" % (op1.size, op1.min(), op1.max()))

    wq = get_dequant("blk.0.attn_q.weight")
    print("wq", wq.shape)
    q_py = wq.T @ op1  # [out=3072]
    ref_q = rd_ref(os.path.join(REF, "ref_capture_v9", "ref_l00_p%02d_q.bin" % pos))["v"]
    nat_q = rd_nat([p for (op, _), ps in recs.items() if op == 3 for p in ps][0])["v"]
    for name, v in (("py", q_py), ("native", nat_q), ("ref", ref_q)):
        print("q_%s norm=%.5f  cos(vs py)=%.9f  rmse=%.6f" %
              (name, np.linalg.norm(v),
               float(np.dot(v, q_py) / (np.linalg.norm(v) * np.linalg.norm(q_py))),
               float(np.sqrt(np.mean((v - q_py) ** 2)))))

    # attention norm -> kv_a -> latent -> kv_b -> V -> wo
    wkv_a = get_dequant("blk.0.attn_kv_a_mqa.weight")
    latent = wkv_a.T @ op1
    norm_w = None
    # attn_kv_a_norm weight is f32 [512]
    t = tensors["blk.0.attn_kv_a_norm.weight"]
    raw = open(GGUF, "rb"); raw.seek(data_start + t["offset"])
    norm_w = np.frombuffer(raw.read(512 * 4), dtype=np.float32).astype(np.float64)
    ss = np.sum(latent * latent) / 512.0
    factor = 1.0 / np.sqrt(ss + 1e-6)
    lat_normed = latent * factor * norm_w
    wkv_b = get_dequant("blk.0.attn_kv_b.weight")
    exp = wkv_b.T @ lat_normed  # [4096] = 16*(128+128)
    heads = 16
    V = np.zeros(heads * 128)
    for h in range(heads):
        V[h * 128:(h + 1) * 128] = exp[h * 256 + 128:h * 256 + 256]
    wo = get_dequant("blk.0.attn_output.weight")
    wo_out = wo.T @ V
    ref_attn = rd_ref(os.path.join(REF, "ref_capture_v9", "ref_l00_p%02d_attn_out.bin" % pos))["v"]
    nat_attn = rd_nat([p for (op, _), ps in recs.items() if op == 5 for p in ps][0])["v"]
    for name, v in (("py", wo_out), ("native", nat_attn), ("ref", ref_attn)):
        print("attn_out_%s norm=%.5f cos(vs py)=%.9f rmse=%.6f" %
              (name, np.linalg.norm(v),
               float(np.dot(v, wo_out) / (np.linalg.norm(v) * np.linalg.norm(wo_out))),
               float(np.sqrt(np.mean((v - wo_out) ** 2)))))

    # our V (from MLA_kv_latent + expanded capture) vs python
    mlalat = [p for (op, _), ps in recs.items() if op == 0 for p in ps]
    mla_exp = None
    for (op, _), ps in recs.items():
        for p in ps:
            if "MLA_expanded" in p:
                mla_exp = rd_nat(p)["v"]
    if mla_exp is not None:
        exp_nat = mla_exp
        V_nat = np.zeros(2048)
        for h in range(heads):
            V_nat[h * 128:(h + 1) * 128] = exp_nat[h * 256 + 128:h * 256 + 256]
        print("V: py_norm=%.5f nat_norm=%.5f cos=%.9f rmse=%.6f" %
              (np.linalg.norm(V), np.linalg.norm(V_nat),
               float(np.dot(V, V_nat) / (np.linalg.norm(V) * np.linalg.norm(V_nat))),
               float(np.sqrt(np.mean((V - V_nat) ** 2)))))
    lat_ref = rd_ref(os.path.join(REF, "ref_capture_v9", "ref_l00_p%02d_kv_cmpr.bin" % pos))["v"]
    print("kv_cmpr: py cos=%.9f rmse=%.6f  (ref norm %.5f vs py norm %.5f)" %
          (float(np.dot(lat_normed, lat_ref) / (np.linalg.norm(lat_normed) * np.linalg.norm(lat_ref))),
           float(np.sqrt(np.mean((lat_normed - lat_ref) ** 2))),
           np.linalg.norm(lat_ref), np.linalg.norm(lat_normed)))
    kpe_ref = rd_ref(os.path.join(REF, "ref_capture_v9", "ref_l00_p%02d_k_pe.bin" % pos))["v"]
    kpe_py = latent[512:576]
    print("k_pe: py cos=%.9f rmse=%.6f" %
          (float(np.dot(kpe_py, kpe_ref) / (np.linalg.norm(kpe_py) * np.linalg.norm(kpe_ref))),
           float(np.sqrt(np.mean((kpe_py - kpe_ref) ** 2)))))


if __name__ == "__main__":
    main()
