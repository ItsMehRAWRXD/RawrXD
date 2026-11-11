#!/usr/bin/env python3
"""Full stage-by-stage native-vs-reference activation parity.

Native records:  DifferentialRecorder format (op_id u32, layer u32, pos u64,
                 ndim u32, dims i64[ndim], count u64, floats).
Reference:       PACT format from the llama.cpp instrumented reference.
"""
import glob
import math
import os
import struct
import sys

REF = r"F:\rawrxd\evidence\RAWRXD_REFERENCE_REPRODUCIBILITY_001\ref_capture_repro"
EV = r"F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001"


def rd_nat(p):
    d = open(p, "rb").read()
    op, layer = struct.unpack_from("<II", d, 0)
    pos = struct.unpack_from("<Q", d, 8)[0]
    (nd,) = struct.unpack_from("<I", d, 16)
    off = 20
    dims = [struct.unpack_from("<q", d, off + 8 * j)[0] for j in range(nd)]
    off += 8 * nd
    (cnt,) = struct.unpack_from("<Q", d, off)
    off += 8
    return {
        "path": os.path.basename(p), "op": op, "layer": layer, "pos": pos,
        "dims": dims, "count": cnt,
        "v": struct.unpack("<%df" % cnt, d[off:off + cnt * 4]),
    }


def rd_ref(p):
    d = open(p, "rb").read()
    (magic,) = struct.unpack_from("<I", d, 0)
    assert magic == 0x54434150, hex(magic)
    (layer,) = struct.unpack_from("<Q", d, 8)
    (nlen,) = struct.unpack_from("<I", d, 16)
    name = d[20:20 + nlen].decode()
    off = 20 + nlen
    (nd,) = struct.unpack_from("<I", d, off)
    off += 4
    dims = [struct.unpack_from("<Q", d, off + 8 * j)[0] for j in range(nd)]
    off += 8 * nd
    return {
        "layer": layer, "name": name, "dims": dims,
        "v": struct.unpack("<%df" % ((len(d) - off) // 4), d[off:]),
    }


def met(a, b):
    n = min(len(a), len(b))
    if n == 0 or n != max(len(a), len(b)):
        return None
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    cos = dot / (na * nb) if na > 0 and nb > 0 else 0.0
    rm = math.sqrt(sum((x - y) ** 2 for x, y in zip(a, b)) / n)
    mx = max(abs(x - y) for x, y in zip(a, b))
    return {"n": n, "cos": cos, "rmse": rm, "max": mx,
            "ratio": (na / nb if nb > 0 else 0.0)}


def ref_layer_name(layer):
    return "l-1" if layer == 26 or layer == (1 << 32) - 1 or layer == 4294967295 else "l%02d" % layer


def main():
    nat_dir = sys.argv[1]
    pos = int(sys.argv[2])
    layers = int(sys.argv[3]) if len(sys.argv) > 3 else 27

    nat = [rd_nat(p) for p in sorted(glob.glob(os.path.join(nat_dir, "*.bin")))]
    nat = [r for r in nat if r["pos"] == pos]
    print("native records at pos %d: %d" % (pos, len(nat)))

    # Reference stage -> per-layer
    # Stage map (verified against tmp_llama-clone/src/models/deepseek2.cpp and
    # the native DifferentialRecorder captures):
    #   ref k_pe is registered BEFORE ggml_rope_ext (deepseek2.cpp:536), so its
    #   native counterpart is MLA_k_rope_raw, not the post-rope MLA_k_rope.
    #   ref ffn_moe_out is routed-experts only while the native MoE_Output is
    #   the fused routed+shared result, so the combined reference ffn_out is
    #   the apples-to-apples comparison for it. The dense lead layer (0) has a
    #   separate down-projection Linear_Output.
    stages = ["inp_embd", "attn_norm", "q", "attn_out", "ffn_norm",
              "ffn_out", "l_out", "kv_cmpr", "k_pe", "result_norm"]

    print("%-22s %8s %8s %12s %12s %12s %10s" %
          ("stage", "layer", "n", "cosine", "rmse", "max|d|", "norm_ratio"))
    worst = []
    for st in stages:
        for L in range(layers):
            refn = "ref_%s_p%02d_%s.bin" % (ref_layer_name(L), pos, st)
            refp = os.path.join(REF, refn)
            if not os.path.exists(refp):
                continue
            r = rd_ref(refp)
            # native counterpart: pick the record for this layer & stage
            if st == "kv_cmpr":
                cand = [x for x in nat if x["layer"] == L and "MLA_kv_latent" in x["path"]]
            elif st == "k_pe":
                # ref k_pe is captured before rope_ext; the native pre-rope
                # record is MLA_k_rope_raw (post-rope has no ref counterpart).
                cand = [x for x in nat if x["layer"] == L and "MLA_k_rope_raw" in x["path"]]
            elif st == "inp_embd":
                cand = [x for x in nat if x["op"] == 0 and "Linear_Output" in x["path"]]
            elif st == "attn_norm":
                cand = [x for x in nat if x["layer"] == L and x["op"] == 1 + 12 * L and "RMSNorm" in x["path"]]
            elif st == "q":
                cand = [x for x in nat if x["layer"] == L and x["op"] == 3 + 12 * L and "Linear_Output" in x["path"]]
            elif st == "attn_out":
                cand = [x for x in nat if x["layer"] == L and x["op"] == 5 + 12 * L and "Linear_Output" in x["path"]]
            elif st == "ffn_norm":
                cand = [x for x in nat if x["layer"] == L and x["op"] == 7 + 12 * L and "RMSNorm" in x["path"]]
            elif st == "ffn_out":
                # dense lead layer: down-projection Linear_Output;
                # MoE layers: the fusedMoE routed+shared output (matches the
                # reference's combined ffn_out, not the routed-only ffn_moe_out)
                cand = [x for x in nat if x["layer"] == L and x["op"] == 10 + 12 * L and "Linear_Output" in x["path"]]
                if not cand:
                    cand = [x for x in nat if x["layer"] == L and "MoE_Output" in x["path"]]
            elif st == "l_out":
                cand = [x for x in nat if x["layer"] == L and x["op"] == 11 + 12 * L and "Output" in x["path"]]
            elif st == "result_norm":
                cand = [x for x in nat if x["layer"] == (1 << 32) - 1 and "RMSNorm" in x["path"] and x["op"] == 297]
            else:
                cand = []
            if not cand:
                continue
            m = met(cand[0]["v"], r["v"])
            if m is None:
                print("%-22s %8d SHAPE %d vs %d" %
                      (st, L, len(cand[0]["v"]), len(r["v"])))
                continue
            print("%-22s %8d %8d %12.8f %12.3g %12.3g %10.6f" %
                  (st, L, m["n"], m["cos"], m["rmse"], m["max"], m["ratio"]))
            worst.append((m["rmse"], st, L))
    worst.sort(reverse=True)
    print("\nworst stages:")
    for rm, st, L in worst[:8]:
        print("  rmse=%.6g  %s layer %d" % (rm, st, L))


if __name__ == "__main__":
    main()
