#!/usr/bin/env python3
"""G06 diagnostic harness: GPU ArenaDown vs Q6_K×Q8_K oracle (primary).

Fail-closed:
  - Primary gate metric: gpu vs q6k×q8k oracle (proposed band max_abs <= 1e-6)
  - Secondary telemetry: gpu vs FP32 scalar (expect ~0.0109 contract delta)
  - Never writes official 25-gate ledger; certified=false; PROMOTE=0
  - Reads sealed capture in-place; writes ONLY into --out-dir (fresh evidence)

Shader contract input: deep2_qgemv.comp type==14 — 256-col Q8_K act quant,
210-byte Q6_K blocks, ArenaFFNAct → ArenaDown.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from k2_gpu_moe_vector_parity import compare  # noqa: E402
from k2_moe_capture_audit import parse_manifest, read_vector  # noqa: E402
from k2_q6k_q8k_oracle import gemv_q6k_q8k  # noqa: E402
from k2_q6k_scalar_oracle import gemv as gemv_fp32  # noqa: E402


PRIMARY_MAX_ABS = 1e-6


def first_exceeding(candidate, reference, limit):
    for i, (a, b) in enumerate(zip(candidate, reference)):
        d = abs(a - b)
        if d > limit:
            return {
                "index": i,
                "candidate": a,
                "reference": b,
                "abs": d,
            }
    return None


def run(manifest: Path, out_dir: Path, primary_max_abs: float) -> dict:
    fields = parse_manifest(manifest)
    stem = manifest.name.removesuffix(".manifest.txt")
    base = manifest.parent / stem
    weights = Path(str(base) + ".down_q6k.bin")
    activation = Path(str(base) + ".post_swiglu.txt")
    cpu = Path(str(base) + ".cpu_down.txt")
    gpu = Path(str(base) + ".gpu_down.txt")

    packed = weights.read_bytes()
    if len(packed) != fields["weight_bytes"]:
        raise ValueError("weight bytes disagree with manifest")

    x, xhash = read_vector(activation, fields["columns"])
    cpu_data, cpuhash = read_vector(cpu, fields["rows"])
    gpu_data, gpuhash = read_vector(gpu, fields["rows"])

    q8k = gemv_q6k_q8k(packed, x, fields["rows"], fields["columns"])
    fp32 = gemv_fp32(packed, x, fields["rows"], fields["columns"])

    out_dir.mkdir(parents=True, exist_ok=True)
    for name in (
        "oracle_q6k_q8k.txt",
        "oracle_fp32.txt",
        "G06_HARNESS_RECEIPT.json",
        "TYPE14_CONTRACT.json",
    ):
        p = out_dir / name
        if p.exists():
            raise ValueError(f"refusing to overwrite {p}")

    (out_dir / "oracle_q6k_q8k.txt").write_text(
        "".join(f"{v:.17g}\n" for v in q8k), encoding="utf-8"
    )
    (out_dir / "oracle_fp32.txt").write_text(
        "".join(f"{v:.17g}\n" for v in fp32), encoding="utf-8"
    )

    m_gpu_q8 = compare(gpu_data, q8k, 1e-8)
    m_gpu_fp32 = compare(gpu_data, fp32, 1e-8)
    m_cpu_fp32 = compare(cpu_data, fp32, 1e-8)
    m_cpu_q8 = compare(cpu_data, q8k, 1e-8)

    primary_ok = (
        m_gpu_q8["max_abs"] <= primary_max_abs
        and m_gpu_q8["nonfinite"] == 0
        and math.isfinite(m_gpu_q8["cosine_similarity"])
    )

    type14 = {
        "schema": "DEEP2_KIMI_TYPE14_CONTRACT_001/v1",
        "shader": "src/deep2/shaders/deep2_qgemv.comp",
        "type": 14,
        "qk_k": 256,
        "q6k_block_bytes": 210,
        "layout": {
            "ql_bytes": 128,
            "qh_bytes": 64,
            "scales_bytes": 16,
            "d_f16_bytes": 2,
            "total": 210,
            "inter_block_padding": 0,
            "trailing_block_padding": 0,
        },
        "activation": {
            "source": "ArenaFFNAct / post_swiglu capture",
            "quant": "per-256 Q8_K; invScale=-127/signedMaxAbs; MAGIC=12582912; clamp[-127,127]",
            "columns_must_be_multiple_of_256": True,
            "columns": fields["columns"],
            "columns_mod_256": fields["columns"] % 256,
        },
        "output": {
            "source": "ArenaDown / gpu_down capture",
            "rows": fields["rows"],
        },
        "boundary_review": {
            "unexpected_padding": False,
            "unexpected_block_boundary_shift": False,
            "notes": [
                "blocksPerRow=(cols+255)/256; rowBytes=blocksPerRow*210 contiguous",
                "Q6_K packed layout matches GGML (no pad between ql/qh/scales/d)",
                "Lane fill zeros only when cols%256!=0; this capture cols%256==0",
                "Scale index mapping half*8+group*2+l//16 matches shader scIndex",
            ],
        },
        "PROMOTE": 0,
        "CERTIFIED": 0,
    }
    (out_dir / "TYPE14_CONTRACT.json").write_text(
        json.dumps(type14, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    receipt = {
        "schema": "DEEP2_KIMI_G06_Q8K_ORACLE_HARNESS_001/v1",
        "status": "PRIMARY_BAND_OK" if primary_ok else "PRIMARY_BAND_FAIL",
        "certified": False,
        "PROMOTE": 0,
        "TIP_CLIMB": "HOLD",
        "CERTIFIED": 0,
        "OFFICIAL_GATES": "UNCHANGED — do not attach G06 PASS without manual review",
        "source_capture": {
            "manifest": str(manifest.resolve()),
            "layer": fields["layer"],
            "expert": fields["expert"],
            "stick": fields["stick"],
            "completion_boundary": fields["completion_boundary"],
            "gpu_submits": fields["gpu_submits"],
            "gpu_arena_owner_expert": fields["gpu_arena_owner_expert"],
        },
        "sha256": {
            "weights": hashlib.sha256(packed).hexdigest(),
            "post_swiglu": xhash,
            "cpu_down": cpuhash,
            "gpu_down": gpuhash,
            "oracle_q6k_q8k": hashlib.sha256(
                (out_dir / "oracle_q6k_q8k.txt").read_bytes()
            ).hexdigest(),
            "oracle_fp32": hashlib.sha256(
                (out_dir / "oracle_fp32.txt").read_bytes()
            ).hexdigest(),
        },
        "primary": {
            "name": "gpu_vs_q6k_q8k_oracle",
            "band_max_abs": primary_max_abs,
            "metrics": m_gpu_q8,
            "band_ok": primary_ok,
            "first_exceeding_band": first_exceeding(gpu_data, q8k, primary_max_abs),
        },
        "secondary_telemetry": {
            "name": "gpu_vs_fp32_scalar_contract_delta",
            "note": "EXPECTED mismatch under VAL-051.11 FP32 CPU vs GPU Q8_K act quant",
            "metrics": m_gpu_fp32,
            "cpu_vs_fp32": m_cpu_fp32,
            "cpu_vs_q8k": m_cpu_q8,
        },
        "type14_contract_path": str((out_dir / "TYPE14_CONTRACT.json").resolve()),
        "anchors_pristine": [
            "KIMI_LAYER39_FIRST_FAIL_001",
            "KIMI_LAYER39_SINGLE_002",
        ],
    }
    (out_dir / "G06_HARNESS_RECEIPT.json").write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return receipt


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--manifest", required=True, type=Path)
    p.add_argument("--out-dir", required=True, type=Path)
    p.add_argument("--primary-max-abs", type=float, default=PRIMARY_MAX_ABS)
    a = p.parse_args(argv)
    if not math.isfinite(a.primary_max_abs) or a.primary_max_abs < 0:
        print("ERROR: invalid primary-max-abs", file=sys.stderr)
        return 3
    try:
        receipt = run(a.manifest, a.out_dir, a.primary_max_abs)
    except (ValueError, OSError, UnicodeError, OverflowError) as exc:
        err = {
            "schema": "DEEP2_KIMI_G06_Q8K_ORACLE_HARNESS_001/v1",
            "status": "ERROR",
            "certified": False,
            "PROMOTE": 0,
            "error": str(exc),
        }
        a.out_dir.mkdir(parents=True, exist_ok=True)
        err_path = a.out_dir / "G06_HARNESS_RECEIPT.json"
        if err_path.exists():
            print(f"ERROR: {exc}", file=sys.stderr)
            return 3
        err_path.write_text(json.dumps(err, indent=2) + "\n", encoding="utf-8")
        print("ERROR")
        return 3
    print(receipt["status"])
    print(f"primary_max_abs={receipt['primary']['metrics']['max_abs']}")
    print(
        "fp32_contract_delta_max_abs="
        f"{receipt['secondary_telemetry']['metrics']['max_abs']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
