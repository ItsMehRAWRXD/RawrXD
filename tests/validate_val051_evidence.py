#!/usr/bin/env python3
"""
VAL-051.2.A Evidence Validator
Parses evidence JSON and verifies deterministic baseline values.
Exit 0 on success, nonzero on any mismatch.
"""

import json
import sys
import os

# Known-good baseline from commit 33f0ff013
BASELINE = {
    "validation_id": "VAL-051-2-A",
    "validation_name": "Real Token Proof Harness",
    "status": "PASS",
    "model_path": r"D:\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf",
    "model_size_bytes": 668788096,
    "model_hash": "sha256:size_668788096_fb_47_lb_3f",
    "prompt": "Hello",
    "input_token_count": 1,
    "output_token_count": 1,
    "sampled_token_id": 9693,
    "output_text": "otto",
    "input_checksum": -5815713594341935019,
    "output_checksum": -5816521735388670104,
    "vocab_size": 32000,
    "embedding_dim": 2048,
    "layer_count": 22,
    "head_count": 32,
    "is_simulated": False,
}

REQUIRED_FIELDS = [
    "validation_id", "validation_name", "timestamp", "status",
    "model_path", "model_size_bytes", "model_hash", "prompt",
    "input_token_count", "output_token_count",
    "input_checksum", "output_checksum",
    "sampled_token_id", "output_text",
    "stages", "tokens_per_second", "throughput_tps",
    "total_duration_ms", "vocab_size", "embedding_dim",
    "layer_count", "head_count", "is_simulated",
]

STAGE_NAMES = ["MODEL_LOAD", "TOKENIZATION", "INFERENCE", "SAMPLING", "DETOKENIZATION"]


def validate_evidence(path):
    errors = []

    if not os.path.exists(path):
        print(f"FAIL: Evidence file not found: {path}")
        return 1

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"FAIL: Invalid JSON in {path}: {e}")
        return 2
    except Exception as e:
        print(f"FAIL: Could not read {path}: {e}")
        return 3

    # Check required fields
    for field in REQUIRED_FIELDS:
        if field not in data:
            errors.append(f"Missing required field: {field}")

    # Check baseline values
    for key, expected in BASELINE.items():
        actual = data.get(key)
        if actual != expected:
            errors.append(f"{key}: expected {expected!r}, got {actual!r}")

    # Check stages array
    stages = data.get("stages", [])
    actual_names = [s.get("name") for s in stages]
    for expected_name in STAGE_NAMES:
        if expected_name not in actual_names:
            errors.append(f"Missing stage: {expected_name}")

    # Check stage statuses
    for stage in stages:
        status = stage.get("status")
        if status != "COMPLETE":
            errors.append(f"Stage {stage.get('name')} not COMPLETE: {status}")

    # Summary
    if errors:
        print(f"FAIL: {len(errors)} error(s) in {path}")
        for err in errors:
            print(f"  - {err}")
        return 10
    else:
        print(f"PASS: Evidence validated successfully: {path}")
        print(f"  Token: {data['sampled_token_id']} -> '{data['output_text']}'")
        print(f"  Duration: {data['total_duration_ms']:.2f} ms")
        print(f"  TPS: {data['tokens_per_second']:.4f}")
        return 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        # Default paths to check
        paths = [
            r"D:\rawrxd\evidence\VAL-051-2-A-EXECUTED.json",
            r"F:\~dev\evidence\VAL-051-2-A-EXECUTED.json",
        ]
    else:
        paths = sys.argv[1:]

    exit_codes = []
    for path in paths:
        code = validate_evidence(path)
        exit_codes.append(code)

    sys.exit(max(exit_codes))
