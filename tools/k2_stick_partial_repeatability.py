#!/usr/bin/env python3
"""Fail-closed repeatability audit of completed aggregate GPU stick captures."""
import argparse
import hashlib
import json
import math
from pathlib import Path

SCHEMA = "DEEP2_KIMI_STICK_PARTIAL_001"


def capture(manifest):
    manifest = Path(manifest)
    if not manifest.name.endswith(".manifest.txt"):
        raise ValueError("manifest suffix required")
    raw = manifest.read_bytes()
    metadata, experts = {}, []
    for line in raw.decode("utf-8").splitlines():
        if not line:
            continue
        if line.startswith("expert="):
            tokens = line.split()
            if len(tokens) != 2 or not tokens[1].startswith("weight="):
                raise ValueError("invalid expert record")
            eid = int(tokens[0][7:])
            weight = float(tokens[1][7:])
            if eid < 0 or not math.isfinite(weight):
                raise ValueError("invalid expert route")
            experts.append((eid, weight))
        else:
            if "=" not in line:
                raise ValueError("invalid manifest record")
            key, value = line.split("=", 1)
            if not key or key in metadata:
                raise ValueError("duplicate manifest field")
            metadata[key] = value
    if metadata.get("schema") != SCHEMA or metadata.get("certified") != "0":
        raise ValueError("invalid schema or certification flag")
    if metadata.get("scope") != "AGGREGATE_STICK_PARTIAL_NOT_INDIVIDUAL_EXPERT":
        raise ValueError("unexpected scope")
    if metadata.get("source") != "K2MoEStickEndDevice":
        raise ValueError("unexpected source")
    layer, stick, rows, count = (int(metadata[k]) for k in
                                ("layer", "stick", "rows", "experts"))
    if layer < 0 or stick not in (0, 1) or not 1 <= rows <= 1048576 or not 1 <= count <= 64:
        raise ValueError("invalid geometry")
    if len(experts) != count or len(set(e for e, _ in experts)) != count:
        raise ValueError("expert count or uniqueness mismatch")
    stem = f"k2_l{layer}_s{stick}_aggregate"
    if manifest.name != stem + ".manifest.txt":
        raise ValueError("manifest identity mismatch")
    vector_raw = manifest.with_name(stem + ".gpu_partial.txt").read_bytes()
    values = []
    for line in vector_raw.decode("utf-8").splitlines():
        token = line.strip()
        if not token:
            raise ValueError("empty vector element")
        value = float(token)
        if not math.isfinite(value):
            raise ValueError("nonfinite vector")
        values.append(value)
    if len(values) != rows:
        raise ValueError("vector size mismatch")
    return {"layer": layer, "stick": stick, "rows": rows,
            "experts": experts, "values": values,
            "manifest_sha256": hashlib.sha256(raw).hexdigest(),
            "vector_sha256": hashlib.sha256(vector_raw).hexdigest()}


def compare(a, b, max_abs_limit, max_rms_limit):
    if not all(math.isfinite(x) and x >= 0 for x in (max_abs_limit, max_rms_limit)):
        raise ValueError("invalid thresholds")
    for name in ("layer", "stick", "rows", "experts"):
        if a[name] != b[name]:
            raise ValueError("nonidentical capture conditions: " + name)
    differences = [x - y for x, y in zip(a["values"], b["values"])]
    maximum = max(map(abs, differences))
    rms = math.sqrt(math.fsum(x * x for x in differences) / a["rows"])
    return {"max_abs": maximum, "rms_abs": rms,
            "mean_abs": math.fsum(map(abs, differences)) / a["rows"],
            "worst_index": max(range(a["rows"]), key=lambda i: abs(differences[i])),
            "within_threshold": maximum <= max_abs_limit and rms <= max_rms_limit}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--first", type=Path, required=True)
    parser.add_argument("--second", type=Path, required=True)
    parser.add_argument("--max-abs", type=float, required=True)
    parser.add_argument("--max-rms", type=float, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.first.resolve() == args.second.resolve():
            raise ValueError("two distinct captures required")
        first, second = capture(args.first), capture(args.second)
        metrics = compare(first, second, args.max_abs, args.max_rms)
        status = "PASS_DIAGNOSTIC" if metrics["within_threshold"] else "FAIL"
        receipt = {
            "schema": "DEEP2_KIMI_STICK_REPEATABILITY_001/v1",
            "status": status, "certified": False, "metrics": metrics,
            "conditions": {k: first[k] for k in ("layer", "stick", "rows", "experts")},
            "first": {k: first[k] for k in ("manifest_sha256", "vector_sha256")},
            "second": {k: second[k] for k in ("manifest_sha256", "vector_sha256")},
            "note": "Aggregate repeatability only, not per-expert numerical parity",
        }
        code = 0 if metrics["within_threshold"] else 2
    except (OSError, ValueError, UnicodeError, OverflowError) as exc:
        receipt = {"schema": "DEEP2_KIMI_STICK_REPEATABILITY_001/v1",
                   "status": "ERROR", "certified": False, "error": str(exc)}
        code = 3
    args.receipt.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n",
                            encoding="utf-8")
    print(receipt["status"])
    return code


if __name__ == "__main__":
    raise SystemExit(main())
