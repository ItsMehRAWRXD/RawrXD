#!/usr/bin/env python3
"""Structurally audit RawrXD's 25 completion-gate evidence without promotion.

Receipt files are NOT cryptographic attestations and cannot by themselves
certify an executable, model, GPU execution, or final release.
"""
import argparse
import hashlib
import json
import re
from pathlib import Path

SHA256 = re.compile(r"^[0-9a-f]{64}$")
GATE_ID = re.compile(r"^G(?:0[1-9]|1[0-9]|2[0-5])$")


def read_json(path):
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path.name}: expected object")
    return data


def validate_manifest(data):
    if data.get("schema") != "RAWRXD_25_GATE_ACCEPTANCE_001/v1":
        raise ValueError("unrecognized manifest schema")
    if data.get("certified") is not False or data.get("tip_climb") != "HOLD":
        raise ValueError("manifest must remain uncertified/hold")
    if data.get("promotion_policy") != "MANUAL_REVIEW_ONLY":
        raise ValueError("automatic release promotion is forbidden")
    if not isinstance(data.get("gates"), list) or len(data["gates"]) != 25:
        raise ValueError("exactly 25 gate declarations required")
    seen = set()
    for idx, gate in enumerate(data["gates"], 1):
        gate_id = f"G{idx:02d}"
        if not isinstance(gate, dict) or gate.get("id") != gate_id:
            raise ValueError(f"gate order/identity mismatch at {idx}")
        if gate.get("id") in seen or not GATE_ID.fullmatch(gate_id):
            raise ValueError("duplicate/invalid gate")
        seen.add(gate_id)
        if (gate.get("status") != "PENDING" or
                gate.get("receipt") != gate_id + ".json" or
                not isinstance(gate.get("title"), str) or not gate["title"].strip()):
            raise ValueError(f"{gate_id}: acceptance definition must remain pending")


def validate_receipt(gate_id, receipt):
    required = ("gate_id", "status", "exit_code", "command",
                "model_sha256", "binary_sha256", "source_sha256",
                "evidence_sha256", "checks")
    if any(k not in receipt for k in required):
        return "INCOMPLETE"
    if receipt["gate_id"] != gate_id:
        return "INVALID_ID"
    if receipt.get("certified") is not False:
        return "UNSAFE_CERTIFICATION"
    if receipt["status"] != "PASS" or type(receipt["exit_code"]) is not int or receipt["exit_code"] != 0:
        return "NOT_PASSING"
    for key in ("model_sha256", "binary_sha256", "source_sha256", "evidence_sha256"):
        if not isinstance(receipt[key], str) or not SHA256.fullmatch(receipt[key]):
            return "INVALID_HASH"
    if not isinstance(receipt["command"], str) or not receipt["command"].strip():
        return "MISSING_COMMAND"
    if not isinstance(receipt["checks"], list) or not receipt["checks"] or not all(
        isinstance(check, dict) and check.get("status") == "PASS"
        and isinstance(check.get("name"), str) and check["name"].strip()
        for check in receipt["checks"]
    ):
        return "CHECKS_NOT_PASSING"
    return "EVIDENCE_PRESENT_UNVERIFIED"


def audit(manifest_path, evidence_dir):
    manifest = read_json(manifest_path)
    validate_manifest(manifest)
    results = []
    for gate in manifest["gates"]:
        path = evidence_dir / gate["receipt"]
        if not path.is_file():
            verdict = "MISSING"
            digest = None
        else:
            raw = path.read_bytes()
            digest = hashlib.sha256(raw).hexdigest()
            try:
                receipt = json.loads(raw.decode("utf-8"))
                verdict = (validate_receipt(gate["id"], receipt)
                           if isinstance(receipt, dict) else "MALFORMED")
            except (ValueError, UnicodeError):
                verdict = "MALFORMED"
        results.append({"id": gate["id"], "phase": gate["phase"],
                        "title": gate["title"], "evidence": path.name,
                        "receipt_sha256": digest, "verification": verdict})
    structural = sum(item["verification"] == "EVIDENCE_PRESENT_UNVERIFIED"
                     for item in results)
    return {
        "schema": "RAWRXD_25_GATE_AUDIT_001/v1",
        "manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        "gate_count": 25,
        "structurally_complete_count": structural,
        "missing_or_failed_count": 25 - structural,
        "status": "EVIDENCE_COMPLETE_UNVERIFIED" if structural == 25 else "HOLD",
        "certified": False,
        "promote": 0, "tip_climb": "HOLD",
        "note": "Only receipt structure checked; no model/GPU execution or hash target verified. Manual release review required.",
        "gates": results,
    }


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--manifest", type=Path, required=True)
    p.add_argument("--evidence-dir", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args(argv)
    if args.output.exists():
        print("ERROR: refusing to overwrite prior audit")
        return 3
    try:
        result = audit(args.manifest, args.evidence_dir)
        rc = 0 if result["structurally_complete_count"] == 25 else 2
    except (OSError, ValueError, UnicodeError) as error:
        result = {"schema": "RAWRXD_25_GATE_AUDIT_001/v1",
                  "status": "ERROR", "certified": False,
                  "promote": 0, "tip_climb": "HOLD", "error": str(error)}
        rc = 3
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(result["status"])
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
