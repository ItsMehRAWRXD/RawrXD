#!/usr/bin/env python3
"""Compare two Deep2 parity traces without treating self-comparison as proof.

The traces contain independent checkpoint summaries emitted by Deep2.  This
tool compares matching (step, checkpoint, layer) records, reports the first
divergence, and fails closed on missing or malformed records.  It is a
diagnostic gate; full-logit binary comparison remains the stronger test.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path


FLOAT_FIELDS = ("MIN", "MAX", "MEAN", "L2")
REQUIRED = ("CP", "COUNT", *FLOAT_FIELDS, "HASH")
TOKEN_RE = re.compile(r"([A-Z_][A-Z_0-9]*)=([^ ]+)")


@dataclass
class Record:
    key: tuple[str, str, str]
    count: int
    values: dict[str, float]
    digest: str


def parse(path: Path) -> dict[tuple[str, str, str], Record]:
    records: dict[tuple[str, str, str], Record] = {}
    for line_number, line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
        if not line.strip() or not line.startswith(("CP=", "STEP=")):
            continue
        fields = dict(TOKEN_RE.findall(line))
        missing = [name for name in REQUIRED if name not in fields]
        if missing:
            raise ValueError(f"{path}:{line_number}: missing fields {missing}")
        step = fields.get("STEP", "-")
        layer = fields.get("LAYER", "-")
        key = (step, fields["CP"], layer)
        if key in records:
            raise ValueError(f"{path}:{line_number}: duplicate checkpoint {key}")
        try:
            count = int(fields["COUNT"])
            values = {name: float(fields[name]) for name in FLOAT_FIELDS}
        except ValueError as exc:
            raise ValueError(f"{path}:{line_number}: invalid numeric field") from exc
        if count < 0 or not all(math.isfinite(value) for value in values.values()):
            raise ValueError(f"{path}:{line_number}: invalid count or non-finite metric")
        records[key] = Record(key, count, values, fields["HASH"].lower())
    if not records:
        raise ValueError(f"{path}: no checkpoint records found")
    return records


def compare(reference: dict, candidate: dict, tolerance: float) -> dict:
    missing = sorted(set(reference) - set(candidate))
    unexpected = sorted(set(candidate) - set(reference))
    differences = []
    for key in sorted(set(reference) & set(candidate)):
        left, right = reference[key], candidate[key]
        metric_delta = {
            name: abs(left.values[name] - right.values[name])
            for name in FLOAT_FIELDS
        }
        hash_match = left.digest == right.digest
        if (left.count != right.count or not hash_match or
                any(delta > tolerance for delta in metric_delta.values())):
            differences.append({
                "key": key,
                "reference": asdict(left),
                "candidate": asdict(right),
                "metric_delta": metric_delta,
                "hash_match": hash_match,
            })
    return {
        "reference_records": len(reference),
        "candidate_records": len(candidate),
        "missing": missing,
        "unexpected": unexpected,
        "differences": differences,
        "passed": not missing and not unexpected and not differences,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("reference", type=Path)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("--tolerance", type=float, default=1e-6)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    if args.tolerance < 0 or not math.isfinite(args.tolerance):
        parser.error("--tolerance must be finite and non-negative")
    try:
        result = compare(parse(args.reference), parse(args.candidate), args.tolerance)
    except (OSError, ValueError) as exc:
        print(f"TRACE_COMPARE=ERROR {exc}", file=sys.stderr)
        return 2
    payload = json.dumps(result, indent=2, sort_keys=True)
    if args.json:
        args.json.write_text(payload + "\n", encoding="utf-8")
    print(f"TRACE_RECORDS={result['reference_records']}/{result['candidate_records']}")
    print(f"TRACE_MISSING={len(result['missing'])}")
    print(f"TRACE_UNEXPECTED={len(result['unexpected'])}")
    print(f"TRACE_DIFFERENCES={len(result['differences'])}")
    print(f"TRACE_PARITY={'PASS' if result['passed'] else 'FAIL'}")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
