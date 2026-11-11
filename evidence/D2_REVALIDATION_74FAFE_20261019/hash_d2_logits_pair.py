#!/usr/bin/env python3
"""Create a compact SHA-256 receipt for every full-vocabulary D2 logit row."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parent
serial = root / "serial_pair_final_logits"
batched = root / "batched_pair_final_logits"
positions = 135
expected_bytes = 32_000 * 4
rows = []
for pos in range(positions):
    name = f"d2_logits_pos{pos}.bin"
    a = (serial / name).read_bytes()
    b = (batched / name).read_bytes()
    if len(a) != expected_bytes or len(b) != expected_bytes:
        raise SystemExit(f"{name}: expected {expected_bytes} bytes; got {len(a)} and {len(b)}")
    ha = hashlib.sha256(a).hexdigest()
    hb = hashlib.sha256(b).hexdigest()
    rows.append({
        "position": pos,
        "bytes": len(a),
        "serial_sha256": ha,
        "batched_sha256": hb,
        "bit_identical": a == b,
    })
result = {
    "serial_directory": str(serial),
    "batched_directory": str(batched),
    "positions": positions,
    "vocabulary_width": 32000,
    "bytes_per_position": expected_bytes,
    "logit_floats_compared": positions * 32000,
    "matching_file_hashes": sum(r["serial_sha256"] == r["batched_sha256"] for r in rows),
    "bit_identical_rows": sum(r["bit_identical"] for r in rows),
    "rows": rows,
}
out = root / "logit_sha256_manifest.json"
out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
print(f"rows={positions} bytes_per_row={expected_bytes} values={positions * 32000}")
print(f"identical_content={result['bit_identical_rows']}/{positions} matching_sha256={result['matching_file_hashes']}/{positions}")
print(f"manifest={out}")
if result["bit_identical_rows"] != positions or result["matching_file_hashes"] != positions:
    raise SystemExit(2)
