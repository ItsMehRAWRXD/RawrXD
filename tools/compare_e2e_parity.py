#!/usr/bin/env python3
"""Per-position logits parity: native (this build) vs llama.cpp reference.

RawrXD reference parities:
  native: F:\\rawrxd\\evidence\\RAWRXD_CORE_DLL_NATIVE_E2E_001\\native_tf_logits_posN.bin
  ref   : F:\\rawrxd\\evidence\\NUGVERSE_ESTIMATOR_001\\ref_logits_posN.bin
"""
import json
import os
import sys

import numpy as np

VAL = 102400


def load_bin(path):
    with open(path, "rb") as f:
        raw = f.read()
    if len(raw) != VAL * 4:
        raise ValueError(f"{path}: {len(raw)} bytes != {VAL*4}")
    return np.frombuffer(raw, dtype=np.float32)


def compare(native_dir_native, ref_dir_ref, positions):
    rows = []
    for pos in positions:
        n_path = native_dir_native % pos
        r_path = ref_dir_ref % pos
        if not os.path.isfile(n_path) or not os.path.isfile(r_path):
            continue
        native = load_bin(n_path)
        ref = load_bin(r_path)
        diff = native - ref
        rmse = float(np.sqrt(np.mean(diff * diff)))
        cos = float(
            np.dot(native, ref) / (np.linalg.norm(native) * np.linalg.norm(ref))
        )
        n_arg = int(native.argmax())
        r_arg = int(ref.argmax())
        rows.append(
            {
                "pos": pos,
                "native_argmax": n_arg,
                "ref_argmax": r_arg,
                "argmax_match": n_arg == r_arg,
                "rmse": rmse,
                "cosine": cos,
                "max_abs_diff": float(np.max(np.abs(diff))),
            }
        )
    return rows


def main():
    ev = r"F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001"
    ref = r"F:\rawrxd\evidence\NUGVERSE_ESTIMATOR_001"
    native_pat = ev + r"\native_tf_logits_pos%d.bin"
    ref_pat = ref + r"\ref_logits_pos%d.bin"

    rows = compare(native_pat, ref_pat, range(0, 20))
    for r in rows:
        print(
            "pos=%2d  native_argmax=%6d  ref_argmax=%6d  match=%s  "
            "rmse=%.6f  cosine=%.10f  max|d|=%.6f"
            % (
                r["pos"],
                r["native_argmax"],
                r["ref_argmax"],
                "YES" if r["argmax_match"] else "NO",
                r["rmse"],
                r["cosine"],
                r["max_abs_diff"],
            )
        )
    ok = all(
        r["argmax_match"] and r["cosine"] > 0.99999 and r["rmse"] < 0.35
        for r in rows
    )
    summary = {"positions": len(rows), "all_match": ok, "rows": rows}
    with open(os.path.join(ev, "attention_logit_parity.json"), "w") as f:
        json.dump(summary, f, indent=2)
    print("ALL_POSITIONS_MATCH=%s" % ("YES" if ok else "NO"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
