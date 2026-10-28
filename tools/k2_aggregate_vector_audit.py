#!/usr/bin/env python3
"""Fail-closed paired GPU/CPU aggregate MoE vector audit.

The manifest is emitted AFTER successful K2MoEStickEndDevice. This audit only
compares completed aggregate vectors; it never certifies individual experts,
GPU SwiGLU activations, or release gates G05/G06.
"""
import argparse
import hashlib
import json
import math
from pathlib import Path

SCHEMA = "DEEP2_KIMI_AGGREGATE_COMPARISON_001"
EXPECTED = {
    "schema": SCHEMA,
    "source": "POST_END_DEVICE_GPU_PARTIAL_AND_COMPLETE_CPU_REFERENCE",
    "scope": "AGGREGATE_ONLY_NOT_PER_EXPERT_PARITY",
    "certified": "0",
}


def read_capture(manifest):
    manifest = Path(manifest)
    fields, experts = {}, []
    raw = manifest.read_bytes()
    for line in raw.decode("utf-8").splitlines():
        if not line:
            raise ValueError("blank manifest line")
        if line.startswith("expert="):
            parts = line.split()
            if len(parts) != 2 or not parts[1].startswith("weight="):
                raise ValueError("bad routed expert record")
            expert_id = int(parts[0][7:])
            weight = float(parts[1][7:])
            if expert_id < 0 or not math.isfinite(weight):
                raise ValueError("invalid expert identity/weight")
            experts.append((expert_id, weight))
            continue
        if "=" not in line:
            raise ValueError("bad manifest field")
        key, val = line.split("=", 1)
        if not key or key in fields:
            raise ValueError("empty or duplicate manifest field")
        fields[key] = val
    if set(fields) != set(EXPECTED) | {"layer", "stick", "rows", "experts"}:
        raise ValueError("missing or unknown manifest field")
    for key, val in EXPECTED.items():
        if fields[key] != val:
            raise ValueError(f"{key}: mismatched schema/provenance")
    layer, stick, rows, count = (int(fields[k]) for k in
                                ("layer", "stick", "rows", "experts"))
    if (layer < 0 or stick not in (0, 1) or
            not 1 <= rows <= 16384 or not 1 <= count <= 64):
        raise ValueError("invalid aggregate geometry")
    if len(experts) != count or len(set(i for i, _ in experts)) != count:
        raise ValueError("missing or duplicate expert routes")
    stem = f"k2_l{layer}_s{stick}_aggregate_comparison"
    if manifest.name != stem + ".manifest.txt":
        raise ValueError("manifest path does not match identity")

    vectors, hashes = {}, {"manifest": hashlib.sha256(raw).hexdigest()}
    for name in ("gpu", "cpu"):
        vector_path = manifest.with_name(stem + f".{name}.txt")
        vector_raw = vector_path.read_bytes()
        numbers = []
        for line in vector_raw.decode("utf-8").splitlines():
            token = line.strip()
            if not token:
                raise ValueError("blank vector element")
            number = float(token)
            if not math.isfinite(number):
                raise ValueError("nonfinite vector element")
            numbers.append(number)
        if len(numbers) != rows:
            raise ValueError(f"{name}: vector length mismatch")
        vectors[name] = numbers
        hashes[name] = hashlib.sha256(vector_raw).hexdigest()
    return {"layer": layer, "stick": stick, "rows": rows,
            "experts": experts, "vectors": vectors, "sha256": hashes}


def compare(record, max_abs, max_rms):
    if not all(math.isfinite(x) and x >= 0 for x in (max_abs, max_rms)):
        raise ValueError("explicit finite nonnegative thresholds required")
    rows = record["rows"]
    gpu, cpu = record["vectors"]["gpu"], record["vectors"]["cpu"]
    # Require both complete vectors before zip; truncated comparisons
    # could otherwise produce a false numerical pass.
    if type(rows) is not int or rows < 1 or len(gpu) != rows or len(cpu) != rows:
        raise ValueError("full-vector length mismatch")
    if any(not math.isfinite(v) for v in gpu) or any(
            not math.isfinite(v) for v in cpu):
        raise ValueError("nonfinite candidate/reference element")
    delta = [a - b for a, b in zip(gpu, cpu)]
    if any(not math.isfinite(v) for v in delta):
        raise ValueError("nonfinite difference")
    sq_sum = math.fsum(v * v for v in delta)
    if not math.isfinite(sq_sum):
        raise ValueError("difference overflow")
    absolute = list(map(abs, delta))
    rms = math.sqrt(sq_sum / record["rows"])
    mean = math.fsum(absolute) / record["rows"]
    result = {
        "elements": record["rows"],
        "max_abs": max(absolute),
        "mean_abs": mean,
        "rms_abs": rms,
        "worst_index": max(range(record["rows"]), key=lambda k: absolute[k]),
        "within_threshold": max(absolute) <= max_abs and rms <= max_rms,
    }
    return result


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--manifest", required=True, type=Path)
    p.add_argument("--max-abs", required=True, type=float)
    p.add_argument("--max-rms", required=True, type=float)
    p.add_argument("--receipt", required=True, type=Path)
    args = p.parse_args(argv)
    if args.receipt.exists():
        print("ERROR: refusing to overwrite receipt")
        return 3
    try:
        record = read_capture(args.manifest)
        metrics = compare(record, args.max_abs, args.max_rms)
        status = "PASS_DIAGNOSTIC" if metrics["within_threshold"] else "FAIL"
        result = {
            "schema": "DEEP2_KIMI_AGGREGATE_VECTOR_AUDIT_001/v1",
            "status": status, "certified": False,
            "gpu_expert_witness": "ABSENT",
            "scope": EXPECTED["scope"],
            "identity": {key: record[key] for key in ("layer", "stick", "rows", "experts")},
            "inputs_sha256": record["sha256"],
            "thresholds": {"max_abs": args.max_abs, "max_rms": args.max_rms},
            "metrics": metrics,
            "promote": 0,
            "note": "Aggregate-only CPU vs GPU diagnostic; no per-expert provenance",
        }
        code = 0 if metrics["within_threshold"] else 2
    except (OSError, ValueError, OverflowError, UnicodeError) as exc:
        result = {
            "schema": "DEEP2_KIMI_AGGREGATE_VECTOR_AUDIT_001/v1",
            "status": "ERROR", "certified": False, "promote": 0,
            "gpu_expert_witness": "ABSENT", "error": str(exc)
        }
        code = 3
    try:
        with args.receipt.open("x", encoding="utf-8") as out:
            json.dump(result, out, indent=2, sort_keys=True)
            out.write("\n")
    except OSError as exc:
        print("ERROR: receipt creation failed:", exc)
        return 3
    print(result["status"])
    return code


if __name__ == "__main__":
    raise SystemExit(main())
