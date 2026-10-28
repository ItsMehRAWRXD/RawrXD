#!/usr/bin/env python3
"""Audit one Kimi GPU0 expert capture against an independent scalar Q6_K oracle.

All files are loaded from the capture manifest stem, with no guessed shape.
A valid diagnostic is NEVER a production numerical certificate.
"""
import argparse
import hashlib
import json
import math
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from k2_q6k_scalar_oracle import gemv
from k2_gpu_moe_vector_parity import compare


def parse_manifest(path):
    fields = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ValueError("invalid manifest line")
        k, v = line.split("=", 1)
        if not k or k in fields:
            raise ValueError("missing or duplicate manifest key")
        fields[k] = v
    for k in ("schema", "layer", "expert", "stick", "ggml_type",
              "rows", "columns", "weight_bytes", "source", "certified",
              "completion_boundary", "gpu_arena_owner_expert",
              "gpu_arena_owner_rule", "gpu_down_buffer_id",
              "gpu_activation_buffer_id", "gpu_submits"):
        if k not in fields:
            raise ValueError(f"missing manifest key: {k}")
    if fields["schema"] != "DEEP2_KIMI_MOE_EXPERT_CAPTURE_001":
        raise ValueError("unknown capture schema")
    if fields["certified"] != "0":
        raise ValueError("capture must explicitly report uncertified")
    if fields["source"] != "GPU_EXPERT_PARITY_DIAGNOSTIC":
        raise ValueError("unexpected capture source")
    if fields["completion_boundary"] != "K2MoEStickEndDevice":
        raise ValueError("capture is not completion-ordered")
    if fields["gpu_arena_owner_rule"] != "LAST_SORTED_WORKLIST_EXPERT":
        raise ValueError("unknown GPU arena ownership rule")
    for k in ("layer", "expert", "stick", "ggml_type", "rows",
              "columns", "weight_bytes", "gpu_arena_owner_expert",
              "gpu_down_buffer_id",
              "gpu_activation_buffer_id", "gpu_submits"):
        val = int(fields[k])
        if val < 0:
            raise ValueError(f"negative manifest field {k}")
        fields[k] = val
    for k in ("gpu_down_buffer_id", "gpu_activation_buffer_id", "gpu_submits"):
        if fields[k] == 0:
            raise ValueError(f"missing completion provenance: {k}")
    if fields["gpu_arena_owner_expert"] != fields["expert"]:
        raise ValueError("arena owner does not match captured expert")
    if fields["ggml_type"] != 14 or not 1 <= fields["rows"] <= 1048576:
        raise ValueError("invalid ggml type or row count")
    if not 1 <= fields["columns"] <= 1048576 or fields["columns"] % 256:
        raise ValueError("invalid column count")
    if fields["weight_bytes"] != fields["rows"] * (fields["columns"] // 256) * 210:
        raise ValueError("manifest weight geometry mismatch")
    return fields


def read_vector(path, expected):
    raw = path.read_bytes()
    result = []
    for line in raw.decode("utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            v = float(line)
            if not math.isfinite(v):
                raise ValueError(f"nonfinite vector element in {path.name}")
            result.append(v)
    if len(result) != expected:
        raise ValueError(f"{path.name}: got {len(result)} floats, expected {expected}")
    return result, hashlib.sha256(raw).hexdigest()


def audit(manifest, max_abs, max_rms, min_cosine):
    fields = parse_manifest(manifest)
    stem = manifest.name.removesuffix(".manifest.txt")
    if not manifest.name.endswith(".manifest.txt"):
        raise ValueError("manifest must end with .manifest.txt")
    expected_stem = f"k2_l{fields['layer']}_e{fields['expert']}_s{fields['stick']}"
    if stem != expected_stem:
        raise ValueError("manifest identity does not match filename")
    base = manifest.parent / stem
    weights = Path(str(base) + ".down_q6k.bin")
    activation = Path(str(base) + ".post_swiglu.txt")
    cpu = Path(str(base) + ".cpu_down.txt")
    gpu = Path(str(base) + ".gpu_down.txt")
    packed = weights.read_bytes()
    if len(packed) != fields["weight_bytes"]:
        raise ValueError("actual weight bytes disagree with manifest")
    x, xhash = read_vector(activation, fields["columns"])
    cpu_data, cpuhash = read_vector(cpu, fields["rows"])
    gpu_data, gpuhash = read_vector(gpu, fields["rows"])
    reference = gemv(packed, x, fields["rows"], fields["columns"])
    metrics = {
        "cpu_vs_scalar_down": compare(cpu_data, reference, 1e-8),
        "gpu_vs_scalar_down": compare(gpu_data, reference, 1e-8),
        "gpu_vs_cpu": compare(gpu_data, cpu_data, 1e-8),
    }
    checks = {name: (m["max_abs"] <= max_abs and m["rms_abs"] <= max_rms
                     and m["cosine_similarity"] >= min_cosine)
              for name, m in metrics.items()}
    return {
        "schema": "DEEP2_KIMI_MOE_CAPTURE_AUDIT_001/v1",
        "status": "PASS_DIAGNOSTIC" if all(checks.values()) else "FAIL",
        "certified": False,
        "manifest": fields,
        "sha256": {
            "manifest": hashlib.sha256(manifest.read_bytes()).hexdigest(),
            "weights": hashlib.sha256(packed).hexdigest(),
            "post_swiglu_cpu": xhash, "cpu_down": cpuhash, "gpu_down": gpuhash
        },
        "limits": {"max_abs": max_abs, "max_rms": max_rms,
                   "min_cosine": min_cosine},
        "checks": checks, "metrics": metrics,
        "limitations": [
            "GPU post-SwiGLU and down vectors are diagnostic post-fence captures;"
            " production certification still requires frozen model provenance",
            "Q6_K unpack must be cross-checked against authoritative GGML fixture",
            "CPU down vector uses existing optimized CPU GEMV",
            "No production certification without model provenance and frozen tolerances",
        ],
    }


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--manifest", required=True, type=Path)
    p.add_argument("--receipt", required=True, type=Path)
    p.add_argument("--max-abs", required=True, type=float)
    p.add_argument("--max-rms", required=True, type=float)
    p.add_argument("--min-cosine", required=True, type=float)
    a = p.parse_args(argv)
    try:
        if (not all(math.isfinite(v) for v in
                    (a.max_abs, a.max_rms, a.min_cosine))
                or a.max_abs < 0 or a.max_rms < 0
                or not -1 <= a.min_cosine <= 1):
            raise ValueError("invalid thresholds")
        result = audit(a.manifest, a.max_abs, a.max_rms, a.min_cosine)
        rc = 0 if result["status"] == "PASS_DIAGNOSTIC" else 2
    except (OSError, UnicodeError, ValueError, OverflowError) as error:
        result = {"schema": "DEEP2_KIMI_MOE_CAPTURE_AUDIT_001/v1",
                  "certified": False, "status": "ERROR", "error": str(error)}
        rc = 3
    a.receipt.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n",
                         encoding="utf-8")
    print(result["status"])
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
