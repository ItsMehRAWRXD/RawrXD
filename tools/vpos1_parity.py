#!/usr/bin/env python3
"""Position-1 V parity: our recorded MLA_V_RECONSTRUCTED (per head, per attended
slot) vs llama.cpp's own v_attn dump for the same step and layer.

If the V we read back for each cached position matches llama.cpp to within
quantization noise, the residual logit error at that position is not a V-source
bug. A wrong slot or a head offset shows up as a near-zero cosine here.
"""
import glob
import os
import struct
import sys

import numpy as np

LAYER = int(sys.argv[1]) if len(sys.argv) > 1 else 0
STEP = int(sys.argv[2]) if len(sys.argv) > 2 else 1
D = r"F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001\llama_layout_probe"
ND = r"F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001\diff_pos1b"


def read_llama(name):
    path = os.path.join(D, "probe_step%02d_%s_l%02d.bin" % (STEP, name, LAYER))
    raw = open(path, "rb").read()
    ne = struct.unpack("<4q", raw[4:36])
    return ne, np.frombuffer(raw[68:], dtype=np.float32).astype(np.float64)


def rec_rows(dirpath, layer, step):
    """All recorded V rows for (layer, step) in recorder emission order."""
    tags = ["_l%d_" % layer, "_l%02d_" % layer, "_l%03d_" % layer]
    pos_tag = "_p%d_" % step
    out = []
    for p in sorted(glob.glob(os.path.join(dirpath, "rec_*"))):
        if "MLA_V_RECONSTRUCTED" not in p:
            continue
        if pos_tag not in p:
            continue
        if not any(t in p for t in tags):
            continue
        b = open(p, "rb").read()
        cnt = struct.unpack_from("<Q", b, 20 + 8)[0]
        out.append(np.frombuffer(
            b[20 + 8 + 8:20 + 8 + 8 + cnt * 4], dtype=np.float32).astype(np.float64))
    return out


def cos(a, b):
    na, nb = np.linalg.norm(a), np.linalg.norm(b)
    return float(a @ b / (na * nb)) if na > 0 and nb > 0 else 0.0


def main():
    for cand in (ND, ND.replace("diff_pos1b", "diff_pos1")):
        rows = rec_rows(cand, LAYER, STEP)
        if rows:
            print("source dir: %s (%d V rows)" % (cand, len(rows)))
            break
    else:
        print("no V rows found for layer %d step %d" % (LAYER, STEP))
        return 1

    nev, vr = read_llama("v_attn")
    # ne=[256, 128, 16]: as with k_attn's [head][slot][dim] reshape, the natural
    # C order is [16][128][256] = [head][dim][slot].
    V = vr.reshape(nev[2], nev[1], nev[0])
    print("llama v_attn ne=%s -> [%d heads][%d dims][%d slots]"
          % (list(nev), V.shape[0], V.shape[1], V.shape[2]))
    print("our V row length: %d, llama head dim: %d"
          % (rows[0].size, V.shape[1]))

    n_slots = STEP + 1
    per_head = len(rows) // 16
    print("rows per head: %d (expected %d)" % (per_head, n_slots))

    print("\nhead   slot   cos(ours,llama)    max|d|        rms")
    cosines = []
    for h in range(16):
        for j in range(min(per_head, V.shape[2])):
            ours = rows[h * per_head + j]
            ref = V[h][:, j]
            c = cos(ours, ref)
            cosines.append(c)
            print("h%-3d   s%-3d   %14.6f  %11.6f  %9.6f"
                  % (h, j, c, float(np.abs(ours - ref).max()),
                     float(np.sqrt(((ours - ref) ** 2).mean()))))
    print("\nmin cos %.6f  mean cos %.6f" % (min(cosines), sum(cosines) / len(cosines)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
