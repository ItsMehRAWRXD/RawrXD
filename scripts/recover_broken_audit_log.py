#!/usr/bin/env python3
"""Quarantine a verified forked AES-GCM audit log and start a new chain.

This tool never edits or discards the original bytes. It only runs when
--apply is supplied, every record authenticates and hashes correctly, and the
caller supplies the independently verified one-based fork location.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import pathlib
import shutil
import sys
from datetime import datetime, timezone


def inspect_chain(log_path: pathlib.Path, key_path: pathlib.Path):
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as exc:
        raise RuntimeError("Python package 'cryptography' is required") from exc

    key = key_path.read_bytes()
    if len(key) != 32:
        raise RuntimeError("audit key must be exactly 32 bytes")

    raw = log_path.read_bytes()
    lines = raw.splitlines()
    records = []
    forks = []
    for number, line in enumerate(lines, start=1):
        if not line:
            raise RuntimeError(f"blank audit record at line {number}")
        try:
            wire = base64.b64decode(line, validate=True)
            if not wire or wire[0] != 1:
                raise ValueError("unknown envelope version")
            terminator = wire.index(0, 1)
            algorithm = wire[1:terminator].decode("ascii")
            if algorithm != "AES-256-GCM":
                raise ValueError("unexpected encryption algorithm")
            start = terminator + 1
            nonce = wire[start:start + 12]
            tag = wire[start + 12:start + 28]
            ciphertext = wire[start + 28:]
            record = json.loads(
                AESGCM(key).decrypt(nonce, ciphertext + tag, None)
            )
        except Exception as exc:
            raise RuntimeError(f"record {number} failed authentication or parsing") from exc

        fields = ("ts", "actor", "action", "resource", "outcome",
                  "detail", "trace_id", "prev_hash")
        canonical = "|".join(str(record[name]) for name in fields)
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        if digest != record.get("hash"):
            raise RuntimeError(f"record {number} content hash does not match")
        if records and record.get("prev_hash") != records[-1].get("hash"):
            parent = next(
                (i for i, prior in enumerate(records, start=1)
                 if prior.get("hash") == record.get("prev_hash")),
                None,
            )
            forks.append({"record": number, "parent_record": parent})
        records.append(record)
    return raw, records, forks


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", required=True, type=pathlib.Path)
    parser.add_argument("--key", required=True, type=pathlib.Path)
    parser.add_argument("--verified-fork-record", required=True, type=int,
                        help="one-based fork record independently verified by the operator")
    parser.add_argument("--apply", action="store_true",
                        help="archive the original and replace the active log with an empty file")
    args = parser.parse_args()

    log_path = args.log.resolve()
    key_path = args.key.resolve()
    try:
        original, records, forks = inspect_chain(log_path, key_path)
        if forks != [{"record": args.verified_fork_record,
                      "parent_record": forks[0]["parent_record"] if forks else None}]:
            raise RuntimeError(
                f"verified fork mismatch: expected only record "
                f"{args.verified_fork_record}, found {forks}"
            )

        digest = hashlib.sha256(original).hexdigest()
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        archive = log_path.with_name(
            f"{log_path.stem}.forked-{timestamp}{log_path.suffix}"
        )
        receipt = log_path.with_name(f"rawrxd_audit_recovery_{timestamp}.json")
        report = {
            "schema": "rawrxd.audit-recovery.v1",
            "detected_at_utc": timestamp,
            "original_log": str(log_path),
            "quarantined_copy": str(archive),
            "original_sha256": digest,
            "record_count": len(records),
            "verified_fork": forks[0],
            "record_authentication": "all AES-256-GCM tags and record hashes verified",
            "action": "preserve original bytes and start a fresh active audit chain",
            "reason": "concurrent audit writers forked from a stale chain head",
        }
        if not args.apply:
            print(json.dumps(report, indent=2))
            print("Dry run only. Re-run with --apply after stopping all RawrXD processes.")
            return 0

        if archive.exists() or receipt.exists():
            raise RuntimeError("recovery archive or receipt already exists")
        shutil.copy2(log_path, archive)
        if hashlib.sha256(archive.read_bytes()).hexdigest() != digest:
            archive.unlink(missing_ok=True)
            raise RuntimeError("quarantine copy did not match the original hash")

        report["quarantined_copy_sha256"] = digest
        receipt_tmp = receipt.with_suffix(receipt.suffix + ".tmp")
        with receipt_tmp.open("x", encoding="utf-8", newline="\n") as out:
            json.dump(report, out, indent=2)
            out.write("\n")
            out.flush()
            os.fsync(out.fileno())

        if hashlib.sha256(log_path.read_bytes()).hexdigest() != digest:
            receipt_tmp.unlink(missing_ok=True)
            raise RuntimeError("active log changed during recovery; left it untouched")

        empty_tmp = log_path.with_suffix(log_path.suffix + ".new")
        with empty_tmp.open("xb") as out:
            out.flush()
            os.fsync(out.fileno())
        os.replace(empty_tmp, log_path)
        os.replace(receipt_tmp, receipt)
        print(json.dumps(report, indent=2))
        return 0
    except Exception as exc:
        print(f"recovery refused: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
