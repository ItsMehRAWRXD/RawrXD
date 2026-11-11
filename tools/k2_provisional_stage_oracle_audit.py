#!/usr/bin/env python3
"""Audit provisional scratch-stage vectors against independent scalar expert.

This is forensic evidence ONLY. EndDevice scratch-buffer identity is UNPROVEN,
even if every comparison passes. G05/G06 and promotion remain blocked.
"""
import argparse
import hashlib
import json
import math
import re
from pathlib import Path

from k2_scalar_input_audit import evaluate
from k2_aggregate_vector_audit import compare

RUN_ID = re.compile(r"[A-Za-z0-9_-]{16,128}\Z")
EXPECTED = {
    "schema": "DEEP2_KIMI_PROVISIONAL_STAGE_001",
    "source": "POST_END_DEVICE_SCRATCH_DOWNLOAD",
    "gpu_buffer_identity": "UNPROVEN",
    "scope": "DIAGNOSTIC_NOT_PER_EXPERT_GPU_PARITY",
    "certified": "0",
}
VECTOR_NAMES = ("gpu_act", "cpu_act", "gpu_down", "cpu_down")


def read_stage(manifest):
    manifest = Path(manifest)
    fields = {}
    manifest_raw = manifest.read_bytes()
    for line in manifest_raw.decode("utf-8").splitlines():
        if not line or "=" not in line:
            raise ValueError("malformed stage manifest")
        key, value = line.split("=", 1)
        if not key or key in fields:
            raise ValueError("duplicate/empty stage field")
        fields[key] = value
    if set(fields) != set(EXPECTED) | {
        "layer", "expert", "stick", "intermediate_dim", "hidden_dim", "run_id"
    }:
        raise ValueError("unexpected or missing stage field")
    for key, value in EXPECTED.items():
        if fields[key] != value:
            raise ValueError("untrusted stage provenance: " + key)
    layer, expert, stick, intermediate, hidden = (
        int(fields[k]) for k in
        ("layer", "expert", "stick", "intermediate_dim", "hidden_dim"))
    if layer < 0 or expert < 0 or stick not in (0, 1):
        raise ValueError("invalid stage identity")
    if not (256 <= hidden <= 16384 and 256 <= intermediate <= 16384
            and hidden % 256 == 0 and intermediate % 256 == 0):
        raise ValueError("invalid stage geometry")
    run_id = fields["run_id"]
    if not RUN_ID.fullmatch(run_id):
        raise ValueError("missing/invalid run identity")
    stem = f"k2_l{layer}_e{expert}_s{stick}_provisional_stage"
    if manifest.name != stem + ".manifest.txt":
        raise ValueError("stage filename identity mismatch")
    vectors = {}
    hashes = {"manifest": hashlib.sha256(manifest_raw).hexdigest()}
    for name in VECTOR_NAMES:
        raw = manifest.with_name(stem + "." + name + ".txt").read_bytes()
        values = []
        for line in raw.decode("utf-8").splitlines():
            if not line.strip():
                raise ValueError("empty stage vector value")
            val = float(line.strip())
            if not math.isfinite(val):
                raise ValueError("nonfinite stage vector")
            values.append(val)
        expected = intermediate if name.endswith("act") else hidden
        if len(values) != expected:
            raise ValueError("stage vector shape mismatch: " + name)
        vectors[name] = values
        hashes[name] = hashlib.sha256(raw).hexdigest()
    return {
        "identity": {"layer": layer, "expert": expert, "stick": stick,
                     "run_id": run_id, "hidden_dim": hidden,
                     "intermediate_dim": intermediate},
        "vectors": vectors, "sha256": hashes,
    }


def analyze(stage_manifest, scalar_manifest, max_abs, max_rms):
    stage = read_stage(stage_manifest)
    meta, scalar_hashes, outputs = evaluate(Path(scalar_manifest))
    identity = stage["identity"]
    for key in ("layer", "expert", "stick", "hidden_dim", "intermediate_dim", "run_id"):
        if identity[key] != meta.get(key):
            raise ValueError("SCALAR_STAGE_IDENTITY_MISMATCH: " + key)
    comparisons = {}
    for label, left, right in (
        ("gpu_act_vs_oracle", stage["vectors"]["gpu_act"], outputs["post_swiglu"]),
        ("cpu_act_vs_oracle", stage["vectors"]["cpu_act"], outputs["post_swiglu"]),
        ("gpu_act_vs_cpu", stage["vectors"]["gpu_act"], stage["vectors"]["cpu_act"]),
        ("gpu_down_vs_oracle", stage["vectors"]["gpu_down"], outputs["down"]),
        ("cpu_down_vs_oracle", stage["vectors"]["cpu_down"], outputs["down"]),
        ("gpu_down_vs_cpu", stage["vectors"]["gpu_down"], stage["vectors"]["cpu_down"]),
    ):
        record = {"rows": len(left), "vectors": {"gpu": left, "cpu": right}}
        comparisons[label] = compare(record, max_abs, max_rms)
    passed = all(v["within_threshold"] for v in comparisons.values())
    return {
        "schema": "DEEP2_KIMI_PROVISIONAL_STAGE_ORACLE_AUDIT_001/v1",
        "status": "PASS_DIAGNOSTIC" if passed else "FAIL",
        "identity": identity, "certified": False, "promote": 0,
        "gpu_buffer_identity": "UNPROVEN",
        "g05_g06": "NOT_CERTIFIED",
        "stage_sha256": stage["sha256"], "scalar_input_sha256": scalar_hashes,
        "thresholds": {"max_abs": max_abs, "max_rms": max_rms},
        "checks": {k: v["within_threshold"] for k, v in comparisons.items()},
        "comparisons": comparisons,
        "note": "Six comparisons are diagnostic; scratch buffer identity is unproven",
    }


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--stage-manifest", type=Path, required=True)
    p.add_argument("--scalar-input-manifest", type=Path, required=True)
    p.add_argument("--max-abs", type=float, required=True)
    p.add_argument("--max-rms", type=float, required=True)
    p.add_argument("--receipt", type=Path, required=True)
    a = p.parse_args(argv)
    if a.receipt.exists():
        print("ERROR: refusing to overwrite prior receipt")
        return 3
    try:
        result = analyze(a.stage_manifest, a.scalar_input_manifest,
                         a.max_abs, a.max_rms)
        rc = 0 if result["status"] == "PASS_DIAGNOSTIC" else 2
    except (OSError, ValueError, UnicodeError, OverflowError) as exc:
        result = {"schema": "DEEP2_KIMI_PROVISIONAL_STAGE_ORACLE_AUDIT_001/v1",
                  "status": "ERROR", "certified": False, "promote": 0,
                  "gpu_buffer_identity": "UNPROVEN",
                  "g05_g06": "NOT_CERTIFIED", "error": str(exc)}
        rc = 3
    try:
        with a.receipt.open("x", encoding="utf-8") as f:
            json.dump(result, f, indent=2, sort_keys=True)
            f.write("\n")
    except OSError as exc:
        print("ERROR: cannot create receipt:", exc)
        return 3
    print(result["status"])
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
