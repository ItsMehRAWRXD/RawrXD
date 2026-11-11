#!/usr/bin/env python3
"""Exercise the audit readiness path with concurrent independent processes."""

from __future__ import annotations

import os
import pathlib
import subprocess
import sys
import tempfile


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: test_audit_multiprocess.py <rawrxd_health_probe.exe>",
              file=sys.stderr)
        return 2

    probe = pathlib.Path(sys.argv[1]).resolve()
    if not probe.is_file():
        print(f"health probe not found: {probe}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="rawrxd-audit-concurrency-") as tmp:
        root = pathlib.Path(tmp)
        audit_dir = root / "audit"
        metrics_dir = root / "metrics"
        key_path = root / "audit.key"
        audit_dir.mkdir()
        metrics_dir.mkdir()
        key_path.write_bytes(os.urandom(32))

        env = os.environ.copy()
        env["RAWRXD_SECURITY_AUDIT_DIR"] = str(audit_dir)
        env["RAWRXD_SECURITY_KEY_FILE"] = str(key_path)
        env["RAWRXD_METRICS_DIR"] = str(metrics_dir)

        workers = 8
        processes = [
            subprocess.Popen(
                [str(probe)], cwd=root, env=env, text=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            for _ in range(workers)
        ]
        failures = []
        for index, process in enumerate(processes, start=1):
            stdout, stderr = process.communicate(timeout=60)
            if process.returncode != 0:
                failures.append(
                    f"worker {index} exit={process.returncode}; "
                    f"stdout={stdout.strip()}; stderr={stderr.strip()}"
                )

        if failures:
            print("FAIL: concurrent audit probe processes did not all pass")
            print("\n".join(failures))
            return 1

        final = subprocess.run(
            [str(probe)], cwd=root, env=env, text=True,
            capture_output=True, timeout=60,
        )
        if final.returncode != 0:
            print("FAIL: final readiness probe found a broken audit chain")
            print(final.stdout.strip())
            print(final.stderr.strip())
            return 1

        lines = (audit_dir / "rawrxd_audit.jsonl").read_text(
            encoding="ascii"
        ).splitlines()
        print(f"PASS: {workers} concurrent processes; final readiness healthy; "
              f"{len(lines)} encrypted audit records")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
