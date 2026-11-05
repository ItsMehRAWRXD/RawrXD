#!/usr/bin/env python3
"""Fail-closed 15-gate RawrXD end-to-end certification receipt checker.

Receipts must be independently produced by the actual Windows/local runtime.
This script does not generate evidence or mark unexecuted tests as passing.
"""
import argparse
import json
from pathlib import Path
import sys
import hashlib

GATES = (
    "E2E_01_SOURCE_BUILD",
    "E2E_02_CTEST",
    "E2E_03_PROTOCOL_PARSER",
    "E2E_04_TOOL_CATALOG",
    "E2E_05_MODEL_TOOL_CALL",
    "E2E_06_MUTATION_AUTHORIZATION",
    "E2E_07_EDITFILES_DISK_WRITE",
    "E2E_08_EDITFILES_DISK_READBACK",
    "E2E_09_TOOL_RESULT_REINJECTION",
    "E2E_10_CANCEL_A_STOP_B",
    "E2E_11_CRASH_RECOVERY",
    "E2E_12_DEEP2_NUMERIC_CORRECTNESS",
    "E2E_13_GPU_CORRECTNESS",
    "E2E_14_SOAK_AND_PACKAGE",
    "E2E_15_INDEPENDENT_CERTIFICATION",
)


def verify(receipt_dir: Path, expected_sha: str) -> list[str]:
    failures = []
    for gate in GATES:
        path = receipt_dir / f"{gate}.json"
        if path.is_symlink():
            failures.append(f"{gate}: receipt must not be a symlink")
            continue
        try:
            receipt = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            failures.append(f"{gate}: missing/invalid receipt ({exc})")
            continue
        if not isinstance(receipt, dict):
            failures.append(f"{gate}: receipt must be a JSON object")
            continue
        if receipt.get("gate") != gate:
            failures.append(f"{gate}: gate identity mismatch")
        if receipt.get("status") != "PASS":
            failures.append(f"{gate}: status is not PASS")
        candidate_hash = receipt.get("candidate_sha256")
        if not isinstance(candidate_hash, str) or candidate_hash.lower() != expected_sha.lower():
            failures.append(f"{gate}: candidate hash mismatch")
        evidence = receipt.get("evidence_path")
        if not isinstance(evidence, str) or not evidence.strip():
            failures.append(f"{gate}: missing evidence path")
            continue
        # Receipts may only reference files within the evidence directory.
        # Never follow an absolute path, traversal, or a symlink escape.
        relative = Path(evidence)
        if relative.is_absolute() or ".." in relative.parts:
            failures.append(f"{gate}: unsafe evidence path")
            continue
        root = receipt_dir.resolve()
        evidence_file = (root / relative).resolve()
        if not evidence_file.is_relative_to(root):
            failures.append(f"{gate}: evidence escapes receipt directory")
            continue
        try:
            if not evidence_file.is_file() or evidence_file.stat().st_size == 0:
                failures.append(f"{gate}: evidence file absent or empty")
                continue
        except OSError as exc:
            failures.append(f"{gate}: evidence inaccessible ({exc})")
            continue
        expected_digest = receipt.get("evidence_sha256")
        if not isinstance(expected_digest, str) or len(expected_digest) != 64 or any(
            c not in "0123456789abcdefABCDEF" for c in expected_digest
        ):
            failures.append(f"{gate}: missing/invalid evidence SHA-256")
            continue
        try:
            digest = hashlib.sha256()
            with evidence_file.open("rb") as source:
                for chunk in iter(lambda: source.read(1024 * 1024), b""):
                    digest.update(chunk)
            actual_digest = digest.hexdigest()
        except OSError as exc:
            failures.append(f"{gate}: evidence unreadable ({exc})")
            continue
        if actual_digest != expected_digest.lower():
            failures.append(f"{gate}: evidence digest mismatch")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--receipt-dir", type=Path, required=True)
    parser.add_argument("--candidate-sha256", required=True)
    args = parser.parse_args()
    sha = args.candidate_sha256
    if len(sha) != 64 or any(c not in "0123456789abcdefABCDEF" for c in sha):
        parser.error("--candidate-sha256 must be a 64-character hexadecimal SHA-256")
    failures = verify(args.receipt_dir, sha)
    for failure in failures:
        print(f"FAIL: {failure}")
    print(f"GATES={len(GATES)}")
    print(f"FAILURES={len(failures)}")
    print(f"CERTIFIED={int(not failures)}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
