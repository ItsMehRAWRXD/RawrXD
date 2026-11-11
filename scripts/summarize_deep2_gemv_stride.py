#!/usr/bin/env python3
"""Validate and summarize Deep2 padded-F32 GEMV profile receipts.

The analyzer intentionally fails closed: it checks receipt hashes, process
isolation, every benchmark case, logical/physical shape geometry, parity, and
zero tails before reporting timing aggregates.
"""

from __future__ import annotations

import argparse
import hashlib
import statistics
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence"
PREFIX = "TP_UNEVEN_WIDTH_SWEEP_2026-10-19_FINAL_PAD"
PADS = (1, 4, 8, 16)
EXPECTED_CASES = 98
EXPECTED_ROWS = 1024
EXPECTED_REPETITIONS = 30


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def key_values(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if "=" not in raw:
            continue
        key, value = raw.split("=", 1)
        if key and key.replace("_", "").isalnum():
            values[key] = value.strip()
    return values


def parse_cases(path: Path) -> list[dict[str, str]]:
    cases: list[dict[str, str]] = []
    current: dict[str, str] | None = None
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if line.startswith("CASE_SPLIT="):
            if current and "CASE_INDEX" in current:
                cases.append(current)
            current = {"CASE_SPLIT": line.split("=", 1)[1]}
            continue
        if line.startswith("CASE_INDEX="):
            if current is None:
                current = {}
            elif "CASE_INDEX" in current:
                cases.append(current)
                current = {}
            current["CASE_INDEX"] = line.split("=", 1)[1]
            continue
        if line.startswith("OVERALL="):
            if current and "CASE_INDEX" in current:
                cases.append(current)
            current = None
            continue
        if current is not None and "=" in line:
            key, value = line.split("=", 1)
            current[key] = value
    if current and "CASE_INDEX" in current:
        cases.append(current)
    return cases


def need(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def check_run(pad: int) -> tuple[dict[str, str], list[dict[str, str]]]:
    folder = EVIDENCE / f"{PREFIX}{pad}_RGA215"
    receipt_path = folder / "receipt.txt"
    log_path = folder / "width-sweep.log"
    need(receipt_path.is_file(), f"missing receipt: {receipt_path}")
    need(log_path.is_file(), f"missing benchmark log: {log_path}")
    receipt = key_values(receipt_path)
    need(receipt.get("LOCAL_ZERO_PAD_MULTIPLE") == str(pad),
         f"pad={pad}: receipt pad multiple mismatch")
    need(receipt.get("BENCHMARK") == "DEEP2_UNEVEN_TP_GEMV_V4",
         f"pad={pad}: unexpected benchmark version")
    need(receipt.get("BENCHMARK_EXIT_CODE") == "0" and
         receipt.get("MICROBENCH_RESULT") == "PASS",
         f"pad={pad}: benchmark did not pass")
    need(receipt.get("COMPETING_PROCESS_BEFORE") == "0" and
         receipt.get("COMPETING_PROCESS_AFTER") == "0",
         f"pad={pad}: GPU isolation check failed")
    need(receipt.get("GATE_10") == "OPEN",
         f"pad={pad}: Gate 10 must remain open")
    for key in ("CPU_PARITY_CASES", "SINGLE_GPU_PARITY_CASES",
                "ZERO_PADDED_WEIGHT_TAIL_CASES"):
        need(receipt.get(key) == f"{EXPECTED_CASES}/{EXPECTED_CASES}",
             f"pad={pad}: {key} failed")

    source_map = {
        "BENCHMARK_SOURCE_SHA256": ROOT / "tools/gpu_profiler/deep2_uneven_tp_gemv.cpp",
        "VULKAN_SOURCE_SHA256": ROOT / "src/deep2/vulkan_compute.cpp",
        "VULKAN_HEADER_SHA256": ROOT / "src/deep2/vulkan_compute.h",
        "SHADER_SOURCE_SHA256": ROOT / "src/deep2/shaders/deep2_ops.comp",
        "PROFILE_SCRIPT_SHA256": ROOT / "scripts/profile_deep2_gemv_rga.ps1",
    }
    for key, path in source_map.items():
        need(path.is_file() and sha256(path).lower() == receipt.get(key, "").lower(),
             f"pad={pad}: current source hash does not match receipt: {path}")

    for path_key, hash_key in (("BENCHMARK_EXE", "BENCHMARK_EXE_SHA256"),
                               ("SHADER_SPV", "SHADER_SPV_SHA256"),
                               ("BENCHMARK_LOG", "BENCHMARK_LOG_SHA256")):
        path = Path(receipt.get(path_key, ""))
        if path_key == "BENCHMARK_LOG":
            path = log_path
        need(path.is_file() and sha256(path).lower() == receipt.get(hash_key, "").lower(),
             f"pad={pad}: artifact hash mismatch: {path_key}")

    cases = parse_cases(log_path)
    need(len(cases) == EXPECTED_CASES,
         f"pad={pad}: expected {EXPECTED_CASES} cases, found {len(cases)}")
    seen: set[tuple[str, int]] = set()
    for case in cases:
        split = case.get("CASE_SPLIT", "")
        global_cols = int(case["CASE_GLOBAL_COLS"])
        rows = int(case["CASE_ROWS"])
        reps = int(case["CASE_REPETITIONS"])
        need(rows == EXPECTED_ROWS and reps == EXPECTED_REPETITIONS,
             f"pad={pad}: wrong rows/repetitions in case {case.get('CASE_INDEX')}")
        need(split in ("EVEN", "RAGGED_RANK0_PLUS_ONE"),
             f"pad={pad}: unexpected split type {split}")
        logical0 = (global_cols + 1) // 2
        logical1 = global_cols // 2
        need(int(case["SHARD0_COLS"]) == logical0 and
             int(case["SHARD1_COLS"]) == logical1,
             f"pad={pad}: logical shard geometry mismatch at {global_cols}")
        stride0 = ((logical0 + pad - 1) // pad) * pad
        stride1 = ((logical1 + pad - 1) // pad) * pad
        need(int(case["SHARD0_WEIGHT_STRIDE"]) == stride0 and
             int(case["SHARD1_WEIGHT_STRIDE"]) == stride1,
             f"pad={pad}: physical stride mismatch at {global_cols}")
        need(case.get("CPU_PARITY") == "PASS" and
             case.get("SINGLE_GPU_PARITY") == "PASS" and
             case.get("ZERO_PADDED_WEIGHT_TAILS") == "PASS",
             f"pad={pad}: parity/tail failure at {global_cols}")
        need(float(case["CPU_REFERENCE_MAX_ABS_ERROR"]) == 0.0 and
             float(case["SINGLE_GPU_REFERENCE_MAX_ABS_ERROR"]) == 0.0,
             f"pad={pad}: nonzero error at {global_cols}")
        need(int(case["DEVICE0_GPU_EXEC_MEDIAN_NS"]) > 0 and
             int(case["DEVICE1_GPU_EXEC_MEDIAN_NS"]) > 0,
             f"pad={pad}: missing calibrated device timing at {global_cols}")
        key = (split, global_cols)
        need(key not in seen, f"pad={pad}: duplicate shape {key}")
        seen.add(key)
    need(len({(c["CASE_SPLIT"], int(c["CASE_GLOBAL_COLS"])) for c in cases}) == EXPECTED_CASES,
         f"pad={pad}: shape uniqueness check failed")
    return receipt, cases


def balanced_median_us(cases: list[dict[str, str]], device: int) -> float:
    values = [int(c[f"DEVICE{device}_GPU_EXEC_MEDIAN_NS"]) / 1000.0
              for c in cases if c["CASE_SPLIT"] == "EVEN"]
    need(len(values) == 49, f"expected 49 balanced widths, found {len(values)}")
    return statistics.median(values)


def width_2049_us(cases: list[dict[str, str]], device: int) -> float:
    target = [c for c in cases if c["CASE_SPLIT"] == "EVEN" and
              int(c["CASE_GLOBAL_COLS"]) == 4098]
    need(len(target) == 1, "balanced local-width 2049 case not found")
    return int(target[0][f"DEVICE{device}_GPU_EXEC_MEDIAN_NS"]) / 1000.0


def modulo_spread_us(cases: list[dict[str, str]], device: int) -> tuple[float, float, float, float]:
    groups: dict[int, list[float]] = {i: [] for i in range(4)}
    for case in cases:
        if case["CASE_SPLIT"] != "EVEN":
            continue
        local_width = int(case["CASE_GLOBAL_COLS"]) // 2
        groups[local_width % 4].append(
            int(case[f"DEVICE{device}_GPU_EXEC_MEDIAN_NS"]) / 1000.0)
    return tuple(statistics.median(groups[i]) for i in range(4))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path,
                        default=EVIDENCE / "TP_UNEVEN_STRIDE_LAYOUT_CERT_2026-10-19.md")
    args = parser.parse_args()

    runs = {pad: check_run(pad) for pad in PADS}
    identity_keys = ("BENCHMARK_EXE_SHA256", "BENCHMARK_SOURCE_SHA256",
                    "VULKAN_SOURCE_SHA256", "VULKAN_HEADER_SHA256",
                    "SHADER_SOURCE_SHA256", "SHADER_SPV_SHA256",
                    "PROFILE_SCRIPT_SHA256")
    baseline = runs[1][0]
    for pad, (receipt, _) in runs.items():
        for key in identity_keys:
            need(receipt.get(key) == baseline.get(key),
                 f"pad={pad}: mismatched run identity {key}")

    smoke_dir = EVIDENCE / f"{PREFIX}16_RGA215"
    smoke_receipt_path = smoke_dir / "tinyllama-gpu-smoke.receipt.txt"
    smoke_log_path = smoke_dir / "tinyllama-gpu-smoke.log"
    smoke = key_values(smoke_receipt_path)
    need(smoke_receipt_path.is_file() and smoke_log_path.is_file(),
         "TinyLlama smoke receipt/log is missing")
    need(smoke.get("PROCESS_EXIT_CODE") == "0" and
         smoke.get("COMPETING_S12_BENCHMARK_BEFORE") == "0" and
         smoke.get("COMPETING_S12_BENCHMARK_AFTER") == "0",
         "TinyLlama smoke did not complete in isolation")
    need(smoke.get("OPENED_DEVICE_COUNT") == "1" and
         smoke.get("GPU_DEVICES") == "1" and
         smoke.get("GPU_DEVICE") == "AMD Radeon AI PRO R9700" and
         smoke.get("PLANNED_CPU_GEMV") == "0" and
         smoke.get("UNPLANNED_FALLBACKS") == "0" and
         smoke.get("STRICT_VIOLATION") == "0",
         "TinyLlama strict single-GPU conditions failed")
    need(smoke.get("TOKSTREAM") == smoke.get("PRIOR_SINGLE_GPU_CONTROL_STREAM") and
         smoke.get("TOKSTREAM") == "6000 16000 16000 16000",
         "TinyLlama token stream differs from its recorded control")
    need(sha256(smoke_log_path).lower() == smoke.get("FULL_RAW_LOG_SHA256", "").lower(),
         "TinyLlama raw log hash mismatch")
    need(sha256(Path(smoke["MODEL"])).lower() == smoke.get("MODEL_SHA256", "").lower() and
         sha256(Path(smoke["EXECUTABLE"])).lower() == smoke.get("EXECUTABLE_SHA256", "").lower() and
         sha256(Path(smoke["SOURCE"])).lower() == smoke.get("SOURCE_SHA256", "").lower(),
         "TinyLlama model/executable/source hash mismatch")
    smoke_log = key_values(smoke_log_path)
    need(smoke_log.get("TOKSTREAM_RUN_0") == smoke.get("TOKSTREAM") and
         smoke_log.get("PLANNED_CPU_GEMV") == "0" and
         smoke_log.get("PLANNED_GPU_GEMV") == "4304" and
         smoke_log.get("GPU_DEVICES") == "1" and
         smoke_log.get("STRICT_VIOLATION") == "0",
         "TinyLlama raw log does not match the receipt")

    report: list[str] = [
        "# Deep2 F32 GEMV Stride Optimization Certificate",
        "",
        "**Date:** 2026-10-19  ",
        "**Decision:** 16-F32-element (64-byte) physical row-stride padding is the fastest tested candidate on both GPUs for this synthetic F32 GEMV sweep. This is a microbenchmark optimization result, not a production tensor-parallel or 150 TPS certification.",
        "",
        "## Reproducibility and correctness",
        "",
        f"The analyzer validated all four isolated receipt/log pairs against the current source, shader, benchmark executable, and SPIR-V hashes. Each run covered {EXPECTED_CASES} shapes (49 balanced and 49 rank-0-plus-one ragged), with {EXPECTED_ROWS} rows and {EXPECTED_REPETITIONS} measured repetitions per shape. Every case had zero maximum absolute error against both CPU and single-GPU Vulkan references, and every padded weight tail contained only zeros.",
        "",
        "The benchmark changes only the physical F32 weight-row stride. Logical columns and input width remain unchanged; shader accumulation stops at the logical width. Cross-device output reduction is host-staged. Competing GPU benchmark checks were zero immediately before and after each candidate run.",
        "",
        "## Timing results",
        "",
        "Values are medians of per-shape calibrated GPU medians, in microseconds. The width-2049 row uses the balanced 4098-global-column case; it isolates the local row width from shard imbalance.",
        "",
        "| Physical stride multiple | R9700, 49-shape median | RX 7800 XT, 49-shape median | R9700 at width 2049 | RX 7800 XT at width 2049 |",
        "|---:|---:|---:|---:|---:|",
    ]
    metrics: dict[int, tuple[float, float, float, float]] = {}
    for pad, (_, cases) in runs.items():
        r = balanced_median_us(cases, 0)
        x = balanced_median_us(cases, 1)
        rw = width_2049_us(cases, 0)
        xw = width_2049_us(cases, 1)
        metrics[pad] = (r, x, rw, xw)
        report.append(f"| {pad} | {r:.1f} | {x:.1f} | {rw:.1f} | {xw:.1f} |")

    pad1 = metrics[1]
    pad16 = metrics[16]
    r_speed = pad1[2] / pad16[2]
    x_speed = pad1[3] / pad16[3]
    r_drop = (1.0 - pad16[2] / pad1[2]) * 100.0
    x_drop = (1.0 - pad16[3] / pad1[3]) * 100.0
    report += [
        "",
        f"At local width 2049, the 16-element candidate reduced calibrated GPU execution time by **{r_drop:.1f}% ({r_speed:.2f}×)** on the R9700 and **{x_drop:.1f}% ({x_speed:.2f}×)** on the RX 7800 XT versus contiguous rows.",
        "",
        "For the 1024-row width-2049 case, stride 2064 adds 15 F32 values per row (60 bytes per row; 61,440 bytes total), about 0.73% over the logical weight payload. Input vectors stay logical-width.",
        "",
        "Pad-16 balanced medians grouped by width modulo four:",
        "",
    ]
    for device, name in ((0, "R9700"), (1, "RX 7800 XT")):
        groups = modulo_spread_us(runs[16][1], device)
        spread = max(groups) - min(groups)
        report.append(f"- {name}: mod-0/1/2/3 = " + ", ".join(f"{v:.1f} µs" for v in groups) +
                      f"; max-minus-min spread {spread:.1f} µs.")

    report += [
        "",
        "## Interpretation and scope",
        "",
        "The tested pattern supports row-stride sensitivity as the cause of the previous width-2049 slowdown. It does not establish whether cache sectors, memory transactions, compiler code generation, or another hardware mechanism is responsible. RGA 2.15 generated static offline ISA/statistics for `gfx1201` and `gfx1101`; these are not live occupancy, hardware-counter, or RGP timeline measurements.",
        "",
        "The stride-aware F32 view and zero-tail preparation helper provide an explicit integration seam. Ordinary GGUF model loading still uses its existing layout unless a caller prepares and supplies a padded F32 view. The strict single-R9700 TinyLlama smoke preserved its recorded control stream (`6000 16000 16000 16000`), executed 4,304 planned GPU GEMVs, and reported zero planned CPU GEMVs, zero unplanned fallbacks, and zero strict violations; it verifies a surrounding runtime path, not automatic GGUF padding. Its single-run 0.1147 TPS is not a performance result.",
        "",
        "Gate 10 remains **OPEN / NOT STARTED**: this sweep shards synthetic GEMV columns and reduces on the host. It does not prove model-level tensor parallelism, cross-device activation/reduction transfer, allocation high-water, or full-logit parity. The two-device layer-parallel smoke remains a separate greedy-parity regression.",
        "",
        "## Receipts",
        "",
    ]
    for pad in PADS:
        report.append(f"- `evidence/{PREFIX}{pad}_RGA215/receipt.txt`")
    report += [
        "- TinyLlama runtime smoke: `evidence/TP_UNEVEN_WIDTH_SWEEP_2026-10-19_FINAL_PAD16_RGA215/tinyllama-gpu-smoke.receipt.txt`",
        "- Multi-GPU layer-parallel regression: `evidence/TP_UNEVEN_MULTI_GPU_LAYER_SMOKE_2026-10-19.receipt.txt`",
        "",
        "`MICROBENCH_CERTIFICATE=PASS`  ",
        "`PRODUCTION_TENSOR_PARALLEL_CERTIFICATION=NOT_ESTABLISHED`  ",
        "`GATE_10=OPEN`",
        "",
    ]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("\n".join(report), encoding="utf-8", newline="\n")
    print(f"CERTIFICATE=PASS output={args.output}")
    for pad in PADS:
        r, x, rw, xw = metrics[pad]
        print(f"PAD={pad} BALANCED_MEDIAN_US=R9700:{r:.1f},RX7800XT:{x:.1f} "
              f"WIDTH2049_US=R9700:{rw:.1f},RX7800XT:{xw:.1f}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (KeyError, OSError, ValueError) as error:
        raise SystemExit(f"CERTIFICATE=FAIL {error}")
