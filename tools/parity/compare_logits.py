#!/usr/bin/env python3
"""Independent teacher-forced logits comparator (stdlib only).

Input JSON schema:
{
  "metadata": {
    "model_sha256": "<64 hex chars>",
    "tokenizer_sha256": "<64 hex chars>",
    "tokens": [1, 42, ...]
  },
  "positions": [
    {"position": 0, "logits": [0.1, -0.2, ...]}
  ]
}
Both files must have identical model/tokenizer hashes and teacher-forced tokens.
This tool compares captured outputs; it does not execute either inference engine.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import sys
from pathlib import Path
from typing import Any


class InputError(ValueError):
    pass


def _load(path: str) -> dict[str, Any]:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise InputError(f"{path}: cannot read valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise InputError(f"{path}: root must be an object")
    metadata = data.get("metadata")
    if not isinstance(metadata, dict):
        raise InputError(f"{path}: missing metadata object")
    for key in ("model_sha256", "tokenizer_sha256"):
        value = metadata.get(key)
        if not isinstance(value, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", value):
            raise InputError(f"{path}: metadata.{key} must be a 64-character SHA-256")
    tokens = metadata.get("tokens")
    if not isinstance(tokens, list) or not tokens or any(type(t) is not int or t < 0 for t in tokens):
        raise InputError(f"{path}: metadata.tokens must be a non-empty array of non-negative integers")
    positions = data.get("positions")
    if not isinstance(positions, list) or not positions:
        raise InputError(f"{path}: positions must be a non-empty array")
    seen = set()
    for item in positions:
        if not isinstance(item, dict) or type(item.get("position")) is not int or item["position"] < 0:
            raise InputError(f"{path}: each position requires a non-negative integer position")
        pos = item["position"]
        if pos in seen:
            raise InputError(f"{path}: duplicate position {pos}")
        seen.add(pos)
        logits = item.get("logits")
        if not isinstance(logits, list) or not logits:
            raise InputError(f"{path}: position {pos} requires a non-empty logits array")
        if any(type(x) not in (int, float) or not math.isfinite(float(x)) for x in logits):
            raise InputError(f"{path}: position {pos} contains non-numeric or non-finite logits")
    data["positions"] = sorted(positions, key=lambda x: x["position"])
    return data


def _cosine(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0.0 or nb == 0.0:
        return 1.0 if na == nb and a == b else 0.0
    return dot / (na * nb)


def compare(reference: dict[str, Any], candidate: dict[str, Any],
            min_mean_cosine: float = 0.9989, min_position_cosine: float = 0.9885,
            min_argmax_rate: float = 0.95, max_rmse: float = 0.05) -> dict[str, Any]:
    rm = reference["metadata"]
    cm = candidate["metadata"]
    for key in ("model_sha256", "tokenizer_sha256", "tokens"):
        if rm[key] != cm[key]:
            raise InputError(f"metadata mismatch: {key}; refusing incomparable runs")
    rp = {x["position"]: x["logits"] for x in reference["positions"]}
    cp = {x["position"]: x["logits"] for x in candidate["positions"]}
    if rp.keys() != cp.keys():
        raise InputError("position sets differ; refusing partial or misaligned comparison")
    rows = []
    for pos in sorted(rp):
        a, b = rp[pos], cp[pos]
        if len(a) != len(b):
            raise InputError(f"position {pos}: vocabulary/logit lengths differ ({len(a)} != {len(b)})")
        a = [float(x) for x in a]
        b = [float(x) for x in b]
        cosine = _cosine(a, b)
        rmse = math.sqrt(sum((x-y) ** 2 for x, y in zip(a, b)) / len(a))
        argmax_match = max(range(len(a)), key=a.__getitem__) == max(range(len(b)), key=b.__getitem__)
        rows.append({"position": pos, "argmax_match": argmax_match,
                     "cosine": cosine, "rmse": rmse})
    count = len(rows)
    mean_cos = sum(x["cosine"] for x in rows) / count
    min_cos = min(x["cosine"] for x in rows)
    argmax_rate = sum(x["argmax_match"] for x in rows) / count
    max_position_rmse = max(x["rmse"] for x in rows)
    passed = (mean_cos >= min_mean_cosine and min_cos >= min_position_cosine
              and argmax_rate >= min_argmax_rate and max_position_rmse <= max_rmse)
    canonical = json.dumps({"metadata": rm, "positions": reference["positions"]},
                            sort_keys=True, separators=(",", ":")).encode()
    return {
        "schema": "rawrxd.logit-parity.v1",
        "verdict": "PASS" if passed else "FAIL",
        "reference_sha256": hashlib.sha256(canonical).hexdigest(),
        "positions_compared": count,
        "argmax_matches": sum(x["argmax_match"] for x in rows),
        "argmax_rate": argmax_rate,
        "mean_cosine": mean_cos,
        "minimum_cosine": min_cos,
        "maximum_position_rmse": max_position_rmse,
        "thresholds": {"min_mean_cosine": min_mean_cosine,
                       "min_position_cosine": min_position_cosine,
                       "min_argmax_rate": min_argmax_rate, "max_rmse": max_rmse},
        "mismatched_positions": [x["position"] for x in rows if not x["argmax_match"]],
        "per_position": rows,
        "scope": "Captured-logit comparison only; does not certify model loading, tokenizer execution, or runtime correctness."
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("reference", help="Independent reference logits JSON")
    parser.add_argument("candidate", help="RawrXD candidate logits JSON")
    parser.add_argument("--min-mean-cosine", type=float, default=0.9989)
    parser.add_argument("--min-position-cosine", type=float, default=0.9885)
    parser.add_argument("--min-argmax-rate", type=float, default=0.95)
    parser.add_argument("--max-rmse", type=float, default=0.05)
    parser.add_argument("--output", help="Write report JSON to this path (stdout otherwise)")
    args = parser.parse_args()
    try:
        report = compare(_load(args.reference), _load(args.candidate),
                         args.min_mean_cosine, args.min_position_cosine,
                         args.min_argmax_rate, args.max_rmse)
    except InputError as exc:
        print(json.dumps({"verdict": "INVALID_INPUT", "error": str(exc)}, indent=2), file=sys.stderr)
        return 2
    rendered = json.dumps(report, indent=2, allow_nan=False) + "\n"
    if args.output:
        Path(args.output).write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    return 0 if report["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
