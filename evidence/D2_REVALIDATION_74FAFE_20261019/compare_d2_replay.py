#!/usr/bin/env python3
"""Compare full-vocabulary D2 logits and summarize real executor receipts."""
import argparse
import hashlib
import json
import math
import re
from pathlib import Path
import numpy as np


def metrics(path):
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    gpu = re.search(r"RUN1: gpu_calls=(\d+) cpu_calls=(\d+) fallback=(\S+) submits=(\d+) waits=(\d+)", text)
    phase = re.search(r"BOUNDARY prefill wall=([\d.]+) ms gpu=([\d.]+) ms host_wait=([\d.]+) ms submit=([\d.]+) ms submits=(\d+)", text)
    device = re.search(r"Selected device: (.+)", text)
    stream = re.search(r"RUN1 GENSTREAM:(.*)", text)
    passed = "RUN1 VERDICT: PASS" in text
    if not gpu or not phase or not device or not passed:
        raise SystemExit(f"invalid executor receipt: {path}")
    return {
        "gpu_calls": int(gpu.group(1)), "cpu_calls": int(gpu.group(2)),
        "fallback": gpu.group(3), "submits": int(gpu.group(4)),
        "waits": int(gpu.group(5)), "wall_ms": float(phase.group(1)),
        "gpu_ms": float(phase.group(2)), "fence_wait_wall_ms": float(phase.group(3)),
        "host_submit_call_ms": float(phase.group(4)), "device": device.group(1).strip(),
        "genstream": stream.group(1).strip() if stream else "",
        "verdict_pass": passed,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--batched-dir", required=True, type=Path)
    ap.add_argument("--serial-dir", required=True, type=Path)
    ap.add_argument("--batched-log", required=True, type=Path)
    ap.add_argument("--serial-log", required=True, type=Path)
    ap.add_argument("--positions", type=int, default=135)
    ap.add_argument("--vocab", type=int, default=32000)
    ap.add_argument("--output", required=True, type=Path)
    args = ap.parse_args()
    expected_bytes = args.vocab * 4
    identical = finite = 0
    total = 0
    mismatches = []
    for pos in range(args.positions):
        name = f"d2_logits_pos{pos}.bin"
        a = (args.batched_dir / name).read_bytes()
        b = (args.serial_dir / name).read_bytes()
        if len(a) != expected_bytes or len(b) != expected_bytes:
            raise SystemExit(f"position {pos}: unexpected bytes {len(a)} / {len(b)}")
        fa = np.frombuffer(a, dtype="<f4")
        fb = np.frombuffer(b, dtype="<f4")
        total += fa.size
        finite += int(bool(np.isfinite(fa).all() and np.isfinite(fb).all()))
        if a == b:
            identical += 1
        else:
            mismatches.append({
                "position": pos,
                "max_abs": float(np.max(np.abs(fa.astype(np.float64) - fb.astype(np.float64)))),
                "argmax_equal": int(np.argmax(fa)) == int(np.argmax(fb)),
            })
    batched = metrics(args.batched_log)
    serial = metrics(args.serial_log)
    submits_saved = serial["submits"] - batched["submits"]
    waits_saved = serial["waits"] - batched["waits"]
    result = {
        "positions": args.positions, "vocab": args.vocab, "logit_floats_compared": total,
        "bit_identical_rows": identical, "finite_rows": finite,
        "mismatches": mismatches, "batched": batched, "serial": serial,
        "submit_reduction_count": submits_saved,
        "submit_reduction_percent": 100.0 * submits_saved / serial["submits"] if serial["submits"] else None,
        "wait_reduction_count": waits_saved,
        "wait_reduction_percent": 100.0 * waits_saved / serial["waits"] if serial["waits"] else None,
        "timing_note": "Host submit API duration, device timestamp duration, and fence-wait wall duration are separate reported measurements. Fence-wait wall overlaps GPU execution; do not sum these durations.",
        "verdict": "PASS" if (identical == args.positions and finite == args.positions and batched["cpu_calls"] == serial["cpu_calls"] == 0 and batched["fallback"] == serial["fallback"] == "<none>" and batched["submits"] < serial["submits"] and batched["waits"] < serial["waits"] and batched["device"] == serial["device"] and batched["verdict_pass"] and serial["verdict_pass"]) else "FAIL",
    }
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"positions={args.positions} vocab={args.vocab} full_logit_floats={total}")
    print(f"bit_identical_rows={identical}/{args.positions} finite_rows={finite}/{args.positions}")
    print(f"device={batched['device']} cpu_fallbacks={batched['cpu_calls']}/{serial['cpu_calls']}")
    print(f"submits={serial['submits']}->{batched['submits']} reduction={result['submit_reduction_percent']:.2f}%")
    print(f"waits={serial['waits']}->{batched['waits']} reduction={result['wait_reduction_percent']:.2f}%")
    for label, m in (("serial", serial), ("batched", batched)):
        print(f"{label}: wall_ms={m['wall_ms']:.1f} gpu_ms={m['gpu_ms']:.1f} host_submit_call_ms={m['host_submit_call_ms']:.1f} fence_wait_wall_ms={m['fence_wait_wall_ms']:.1f}")
    print(f"D2_PARITY_VERDICT={result['verdict']}")
    if result["verdict"] != "PASS":
        raise SystemExit(2)


if __name__ == "__main__":
    main()
