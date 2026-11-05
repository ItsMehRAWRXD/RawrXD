#!/usr/bin/env python3
"""Fail-closed, portable verification of RawrXD's 15 certification receipts.

This checks evidence integrity, not the native Windows product itself.
"""
import argparse
import hashlib
import json
import re
from pathlib import Path

GATES = (
    "t05_cancel", "model_tool_call", "disk_persistence", "tool_reinjection",
    "deep2_numeric", "gpu_inference", "t10_recovery", "t18_soak",
    "t19_stress", "tool_authority", "ide_integration", "multi_agent",
    "clean_build", "t24_package", "t25_certification",
)


def validate(root, manifest):
    errors = []
    if not isinstance(manifest, dict):
        return ["manifest must be an object"]
    candidate = manifest.get("candidate_sha256")
    head = manifest.get("source_commit")
    if not isinstance(candidate, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", candidate):
        errors.append("invalid candidate SHA-256")
    if not isinstance(head, str) or not re.fullmatch(r"[0-9a-fA-F]{40}", head):
        errors.append("invalid source commit SHA")
    gates = manifest.get("gates")
    if not isinstance(gates, dict):
        return errors + ["gates must be an object"]
    for name in GATES:
        entry = gates.get(name)
        if not isinstance(entry, dict) or entry.get("status") != "PASS":
            errors.append(name + ": not PASS")
            continue
        rel = entry.get("receipt")
        if not isinstance(rel, str) or not rel or "\\" in rel:
            errors.append(name + ": invalid receipt path")
            continue
        path = Path(rel)
        if path.is_absolute() or ".." in path.parts:
            errors.append(name + ": unsafe receipt path")
            continue
        try:
            target = (root / path).resolve()
        except (OSError, RuntimeError):
            errors.append(name + ": unresolvable receipt path")
            continue
        if not target.is_relative_to(root.resolve()) or not target.is_file():
            errors.append(name + ": receipt absent or outside evidence root")
            continue
        try:
            raw = target.read_bytes()
            receipt = json.loads(raw)
        except (OSError, ValueError, UnicodeError, RecursionError):
            errors.append(name + ": invalid receipt JSON")
            continue
        if not isinstance(receipt, dict):
            errors.append(name + ": receipt must be an object")
            continue
        if receipt.get("gate") != name or receipt.get("result") != "PASS":
            errors.append(name + ": receipt gate/result mismatch")
        if not isinstance(receipt.get("candidate_sha256"), str) or receipt["candidate_sha256"].lower() != candidate.lower() if isinstance(candidate, str) else True:
            errors.append(name + ": candidate SHA mismatch")
        if not isinstance(receipt.get("source_commit"), str) or receipt["source_commit"].lower() != head.lower() if isinstance(head, str) else True:
            errors.append(name + ": source commit mismatch")
        stamp = receipt.get("timestamp_utc")
        if not isinstance(stamp, str) or not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", stamp):
            errors.append(name + ": missing UTC timestamp")
        digest = entry.get("receipt_sha256")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", digest) or hashlib.sha256(raw).hexdigest() != digest.lower():
            errors.append(name + ": receipt digest mismatch")
    if set(gates) - set(GATES):
        errors.append("unexpected gate IDs")
    if manifest.get("certified") is not True or manifest.get("promote") is not True:
        errors.append("certification/promotion not approved")
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--evidence-root", type=Path, default=Path("."))
    args = parser.parse_args()
    try:
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
        errors = validate(args.evidence_root, manifest)
    except (OSError, ValueError, UnicodeError) as exc:
        errors = [str(exc)]
    print(json.dumps({"verdict": "PASS" if not errors else "NOT_VERIFIED",
                      "gates_required": len(GATES), "errors": errors}, indent=2))
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
