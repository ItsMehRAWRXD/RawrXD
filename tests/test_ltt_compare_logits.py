#!/usr/bin/env python3
"""Regression tests for tools/ltt_compare_logits.py (stdlib only)."""
import json
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "tools" / "ltt_compare_logits.py"


def write(path, rows):
    with path.open("wb") as f:
        for row in rows:
            f.write(struct.pack("<Q", len(row)))
            f.write(struct.pack("<%df" % len(row), *row))


def run_case(root, a, b, expect, extra=()):
    left, right, receipt = root / "left.bin", root / "right.bin", root / "receipt.json"
    write(left, a)
    write(right, b)
    cmd = [sys.executable, str(SCRIPT), "--ltt", str(left),
           "--reference", str(right), "--receipt", str(receipt),
           "--tokens", "10,11,12", "--model-sha256", "a" * 64,
           "--exe-sha256", "b" * 64, "--reference-exe-sha256", "c" * 64,
           *extra]
    p = subprocess.run(cmd, capture_output=True, text=True)
    result = json.loads(receipt.read_text(encoding="utf-8"))
    assert (p.returncode == 0) == expect, (p.stdout, p.stderr, result)
    assert result["status"] == ("PASS" if expect else "FAIL")


def main():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        good = [[float(i) for i in range(20)] for _ in range(3)]
        run_case(root, good, good, True)
        bad = [row[:] for row in good]
        bad[1][0] = 100.0
        run_case(root, good, bad, False)
        run_case(root, good, good[:2], False)
        malformed = root / "left.bin"
        malformed.write_bytes(b"\x01")
        cmd = [sys.executable, str(SCRIPT), "--ltt", str(malformed),
               "--reference", str(root / "right.bin"),
               "--receipt", str(root / "receipt.json"), "--tokens", "10,11,12",
               "--model-sha256", "a" * 64, "--exe-sha256", "b" * 64,
               "--reference-exe-sha256", "c" * 64]
        assert subprocess.run(cmd, capture_output=True).returncode != 0
        assert json.loads((root / "receipt.json").read_text())["status"] == "FAIL"
    print("LTT_PARITY_COMPARATOR_TESTS_PASS")


if __name__ == "__main__":
    main()
