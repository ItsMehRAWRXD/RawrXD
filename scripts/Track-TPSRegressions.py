#!/usr/bin/env python3
"""Phase 2 throughput regression gate.

The gate runs each model three times and only certifies a model when the
three runs agree with each other. A run that is slow because the engine
regressed and a run that is slow because the machine was busy look the same
from a single measurement, so the gate does not look at one run: it looks at
the spread of three.

The engine prints its throughput on one line with fixed key=value pairs:

    [TPS] decode_tps=0.6482 tokens=8 elapsed_ms=12345.6 steps=8

The gate reads that line and nothing else. The engine's own progress
narrative is muted while the measured region runs, so the number reflects the
work and not the logging.

The engine is invoked with its output streams merged (2>&1) so the metric and
the diagnostics arrive on the same stream and neither is lost to a pipe
buffer.

Paths are resolved relative to this file, not to the working directory, so
the gate behaves the same however it is launched. Every path can be
overridden through the environment:

    DEEP2_ENGINE_EXE   path to the engine binary
    DEEP2_MODELS_DIR   directory to scan for models
    DEEP2_BENCH_MODELS explicit list of model files, separated by ';'
    DEEP2_TPS_HISTORY  path to the CSV history file
"""

import argparse
import csv
import math
import os
import re
import subprocess
import sys
from datetime import datetime

# The gate's own constants.
REQUIRED_SWEEPS = 3
MAX_SIGMA = 0.05                 # maximum relative standard deviation, 5%
MIN_MEAN_TPS = 0.0               # a model that reports no throughput has failed
RUN_TIMEOUT_SECONDS = 600
DEFAULT_STEPS = 3                # decode steps per sweep
DEFAULT_SWEEPS = REQUIRED_SWEEPS  # sweeps per model

# A model larger than this is skipped by default. The 5 GB and 10 GB models
# in the local set take longer than a sweep is allowed to take, and running
# them would turn the gate into a multi-hour job. Name them in
# DEEP2_BENCH_MODELS to include them.
MAX_MODEL_BYTES = 2 * 1024 * 1024 * 1024

# The container formats the engine can open. A .gguf is a GGUF file; a .rom
# is the same container under the engine's own name; a .nqb is the quantized
# form of the same thing.
MODEL_SUFFIXES = (".gguf", ".rom", ".nqb")

# The metric line the engine prints. The compute fields are optional, so
# they are matched separately.
TPS_PATTERN = re.compile(
    r"^\[TPS\]\s+decode_tps=([0-9.]+)\s+tokens=(\d+)\s+elapsed_ms=([0-9.]+)"
    r"(?:\s+steps=(\d+))?(?:\s+compute_ms=([0-9.]+))?(?:\s+placement_ms=([0-9.]+))?"
    r"(?:\s+wall_tps=([0-9.]+))?"
)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPT_DIR)



def resolve_engine(override=None):
    """Locate the engine binary."""
    if override:
        if not os.path.isfile(override):
            raise SystemExit(f"[CRITICAL] the engine binary does not exist: {override}")
        return override

    env = os.environ.get("DEEP2_ENGINE_EXE")
    if env:
        if not os.path.isfile(env):
            raise SystemExit(f"[CRITICAL] DEEP2_ENGINE_EXE does not exist: {env}")
        return env

    candidates = [
        os.path.join(REPO_ROOT, "build", "bin", "Release", "Deep2Engine_Benchmark.exe"),
        os.path.join(REPO_ROOT, "build", "bin", "Deep2Engine_Benchmark.exe"),
        os.path.join(REPO_ROOT, "build", "bin", "Release", "Deep2Engine.exe"),
        os.path.join(REPO_ROOT, "build", "bin", "Deep2Engine.exe"),
        os.path.join(REPO_ROOT, "build", "Deep2Engine_Benchmark.exe"),
    ]
    for path in candidates:
        if os.path.isfile(path):
            return path
    raise SystemExit(
        "[CRITICAL] Compiled benchmark executable not found.\n"
        "  Looked for:\n" + "".join(f"    {c}\n" for c in candidates) +
        "  Build it with: cmake -S . -B build && cmake --build build --config Release "
        "--target Deep2Engine_Benchmark\n"
        "  Or pass --bin, or set DEEP2_ENGINE_EXE."
    )


def resolve_models_dir(override=None):
    if override:
        if not os.path.isdir(override):
            raise SystemExit(f"[CRITICAL] the models directory does not exist: {override}")
        return override

    env = os.environ.get("DEEP2_MODELS_DIR")
    if env:
        if not os.path.isdir(env):
            raise SystemExit(f"[CRITICAL] DEEP2_MODELS_DIR does not exist: {env}")
        return env

    candidates = [
        r"G:\~dev\rawrxd\models",
        os.path.join(REPO_ROOT, "models"),
    ]
    for path in candidates:
        if os.path.isdir(path):
            return path
    raise SystemExit(
        "[CRITICAL] No models directory found.\n"
        "  Looked for:\n" + "".join(f"    {c}\n" for c in candidates) +
        "  Set DEEP2_MODELS_DIR to the directory holding the models."
    )


def discover_models(models_dir, explicit_models=None):
    """Find the models the gate will sweep.

    An explicit list wins: the --model arguments, then the
    DEEP2_BENCH_MODELS environment variable. Otherwise the directory is
    scanned for the container formats the engine can open.
    """
    if explicit_models:
        models = list(explicit_models)
    else:
        env = os.environ.get("DEEP2_BENCH_MODELS", "").strip()
        models = [p for p in env.split(";") if p.strip()] if env else []

    if models:
        missing = [p for p in models if not os.path.isfile(p)]
        if missing:
            raise SystemExit("[CRITICAL] these models do not exist:\n" +
                             "".join(f"  {p}\n" for p in missing))
        return models

    models = []
    for name in sorted(os.listdir(models_dir)):
        path = os.path.join(models_dir, name)
        if not os.path.isfile(path):
            continue
        if not name.lower().endswith(MODEL_SUFFIXES):
            continue
        size = os.path.getsize(path)
        if size == 0:
            # A placeholder left behind by the model publisher.
            print(f"[SKIP] {name}: empty file")
            continue
        if size > MAX_MODEL_BYTES:
            print(f"[SKIP] {name}: {size / (1024 ** 3):.2f} GB is over the sweep size limit")
            continue
        models.append(path)

    if not models:
        print(f"[WARN] No model containers found in {models_dir}.")
    return models


def parse_tps(output):
    """Pull the throughput metric out of an engine run."""
    for line in output.splitlines():
        match = TPS_PATTERN.match(line.strip())
        if match:
            tps = float(match.group(1))
            tokens = int(match.group(2))
            elapsed = float(match.group(3))
            steps = int(match.group(4)) if match.group(4) else tokens
            compute = float(match.group(5)) if match.group(5) else None
            placement = float(match.group(6)) if match.group(6) else None
            wall = float(match.group(7)) if match.group(7) else None
            return {"decode_tps": tps, "tokens": tokens, "elapsed_ms": elapsed,
                    "steps": steps, "compute_ms": compute, "placement_ms": placement,
                    "wall_tps": wall}
    return None


def run_sweep(engine, model, steps, timeout, verbose=False):
    """Run the engine once and return its throughput."""
    cmd = [engine, "--benchmark", model, str(steps)]
    try:
        # stderr is merged into stdout so the metric and the diagnostics
        # arrive on one stream.
        completed = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return None, "execution exceeded the sweep deadline"

    if verbose:
        for line in completed.stdout.splitlines():
            if line.startswith("[TIMING]") or line.startswith("[BENCH]"):
                print(f"    {line}")

    metric = parse_tps(completed.stdout)
    if metric is None:
        tail = "\n".join(completed.stdout.splitlines()[-8:])
        return None, f"no throughput metric in the output (exit {completed.returncode})\n{tail}"
    return metric, None


def verify_production_performance_gate(runs):
    """Certify a model from its sweeps.

    `runs` is a list of metric dicts, oldest first. The gate needs at least
    REQUIRED_SWEEPS of them and looks at the most recent ones.

    The measure of consistency is the sample standard deviation of the
    decode rates, taken as a fraction of their mean. A model whose three
    runs differ by more than 5% of the mean has not been measured
    reproducibly, and a single fast or slow run in that set says nothing
    about which one is right.
    """
    if len(runs) < REQUIRED_SWEEPS:
        print(f"[GATE LOCKED] Require {REQUIRED_SWEEPS} reproducible traces. Current: {len(runs)}")
        return False

    target = runs[-REQUIRED_SWEEPS:]
    decode_rates = [run["decode_tps"] for run in target]

    mean_tps = sum(decode_rates) / len(decode_rates)
    if mean_tps <= MIN_MEAN_TPS:
        print("[GATE FAILED] Mean decode rate is zero; the engine produced no throughput.")
        return False

    # Sample standard deviation: the runs are a sample of the engine's
    # behaviour, not the whole population, so the sum of squares is divided
    # by n - 1.
    variance = sum((rate - mean_tps) ** 2 for rate in decode_rates) / (len(decode_rates) - 1)
    stdev = math.sqrt(variance)
    relative_stdev = stdev / mean_tps

    spread = max(decode_rates) - min(decode_rates)
    relative_spread = spread / mean_tps

    print(f"[METRIC] Sustained Decode Speed: {mean_tps:.4f} TPS")
    print(f"[METRIC] Sweeps: {', '.join(f'{r:.4f}' for r in decode_rates)}")
    print(f"[METRIC] Std Dev: {stdev:.4f} TPS ({relative_stdev * 100:.2f}% of the mean)")
    print(f"[METRIC] Peak to Peak: {spread:.4f} TPS ({relative_spread * 100:.2f}% of the mean)")

    # The placement is reported because it is a large fixed cost that a
    # change in the residency policy moves. It is not part of the gate: the
    # gate is about the compute rate, and the placement is setup.
    placements = [r["placement_ms"] for r in target if r.get("placement_ms") is not None]
    if placements:
        print(f"[METRIC] Placement per step: {sum(placements) / len(placements):.1f} ms "
              f"(host dequantization and device upload)")

    if relative_stdev > MAX_SIGMA:
        print(f"[GATE FAILED] Throughput variance {relative_stdev * 100:.2f}% exceeds the "
              f"{MAX_SIGMA * 100:.0f}% sigma threshold.")
        return False

    print("[GATE CLEAN] Performance verified and certified.")
    return True


def build_parser():
    parser = argparse.ArgumentParser(
        prog="Track-TPSRegressions.py",
        description="Phase 2 throughput regression gate. Runs each model three times and "
                    "certifies it only when the three runs agree with each other.",
    )
    parser.add_argument("--bin", dest="binary", default=None,
                        help="path to the engine binary (default: the local build)")
    parser.add_argument("--model", dest="models", action="append", default=None,
                        help="a model to sweep; repeat the flag for more than one")
    parser.add_argument("--models-dir", dest="models_dir", default=None,
                        help="directory to scan for models when --model is not given")
    parser.add_argument("--steps", dest="steps", type=int, default=DEFAULT_STEPS,
                        help="decode steps per sweep")
    parser.add_argument("--sweeps", dest="sweeps", type=int, default=DEFAULT_SWEEPS,
                        help="sweeps per model; the gate needs at least 3")
    parser.add_argument("--timeout", dest="timeout", type=int, default=RUN_TIMEOUT_SECONDS,
                        help="per-sweep deadline in seconds")
    parser.add_argument("--history", dest="history", default=None,
                        help="path to the CSV history file")
    parser.add_argument("--verbose", dest="verbose", action="store_true",
                        help="print the engine's phase timing for every sweep")
    parser.add_argument("--self-test", dest="self_test", action="store_true",
                        help="check the gate arithmetic and exit")
    return parser


def main():
    args = build_parser().parse_args()

    if args.self_test:
        # Exercises the gate arithmetic without a model or a GPU.
        good = [{"decode_tps": 10.0, "tokens": 8, "elapsed_ms": 800.0, "placement_ms": 100.0},
                {"decode_tps": 10.1, "tokens": 8, "elapsed_ms": 792.0, "placement_ms": 100.0},
                {"decode_tps": 9.9, "tokens": 8, "elapsed_ms": 808.0, "placement_ms": 100.0}]
        bad = [{"decode_tps": 10.0, "tokens": 8, "elapsed_ms": 800.0, "placement_ms": 100.0},
               {"decode_tps": 14.0, "tokens": 8, "elapsed_ms": 571.0, "placement_ms": 100.0},
               {"decode_tps": 9.0, "tokens": 8, "elapsed_ms": 888.0, "placement_ms": 100.0}]
        assert verify_production_performance_gate(good) is True, "a stable set must pass"
        assert verify_production_performance_gate(bad) is False, "a spread set must fail"
        assert verify_production_performance_gate(good[:2]) is False, "two sweeps must not pass"
        print("[SELF TEST] the gate arithmetic is correct")
        return 0

    sweeps = max(args.sweeps, REQUIRED_SWEEPS)
    if args.sweeps < REQUIRED_SWEEPS:
        print(f"[NOTE] The gate needs at least {REQUIRED_SWEEPS} sweeps; using {sweeps}.")

    engine = resolve_engine(args.binary)

    if args.models:
        models = discover_models(None, args.models)
        models_label = ", ".join(os.path.basename(m) for m in models)
    else:
        models_dir = resolve_models_dir(args.models_dir)
        models = discover_models(models_dir)
        models_label = models_dir

    history_path = args.history or os.environ.get(
        "DEEP2_TPS_HISTORY",
        os.path.join(REPO_ROOT, "build", "tps_regression_history.csv"),
    )

    print("=" * 60)
    print("  PHASE 2 THROUGHPUT REGRESSION GATE")
    print("=" * 60)
    print(f"  engine : {engine}")
    print(f"  models : {models_label}")
    print(f"  sweeps : {sweeps} per model, {args.steps} steps per sweep, "
          f"{MAX_SIGMA * 100:.0f}% sigma threshold")
    print(f"  history: {history_path}")
    print()

    if not models:
        print("[FAIL] No models to sweep.")
        return 1

    os.makedirs(os.path.dirname(history_path), exist_ok=True)
    history_exists = os.path.isfile(history_path)
    results = []
    failures = 0

    with open(history_path, mode="a", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        if not history_exists:
            writer.writerow(["Timestamp", "ModelName", "Throughput_TPS", "StdDev_TPS",
                             "RelativeStdDev", "PlacementMs", "Status"])

        for model in models:
            name = os.path.basename(model)
            print(f"[PROFILING] {name}")

            runs = []
            for sweep in range(sweeps):
                metric, error = run_sweep(engine, model, args.steps, args.timeout, args.verbose)
                if metric is None:
                    print(f"  -> [FAIL] sweep {sweep + 1}: {error}")
                    runs = []
                    break
                print(f"  -> sweep {sweep + 1}: {metric['decode_tps']:.4f} TPS "
                      f"({metric['tokens']} tokens in {metric['elapsed_ms']:.1f} ms)")
                runs.append(metric)

            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            if not runs:
                writer.writerow([timestamp, name, "0.000", "0.000", "0.000", "0.000",
                                 "EXECUTION_FAILED"])
                failures += 1
                continue

            passed = verify_production_performance_gate(runs)
            if not passed:
                failures += 1

            scored = runs[-REQUIRED_SWEEPS:]
            mean_tps = sum(r["decode_tps"] for r in scored) / len(scored)
            variance = sum((r["decode_tps"] - mean_tps) ** 2 for r in scored) / max(
                1, (len(scored) - 1))
            stdev = math.sqrt(variance)
            relative = stdev / mean_tps if mean_tps > 0 else 0.0
            placements = [r["placement_ms"] for r in scored if r.get("placement_ms") is not None]
            mean_placement = sum(placements) / len(placements) if placements else 0.0
            status = "CERTIFIED" if passed else "VARIANCE_EXCEEDED"
            writer.writerow([timestamp, name, f"{mean_tps:.4f}", f"{stdev:.4f}",
                             f"{relative:.4f}", f"{mean_placement:.1f}", status])
            results.append((name, mean_tps, relative, passed))
            print()

    print("=" * 60)
    for name, mean_tps, relative, passed in results:
        print(f"  {'PASS' if passed else 'FAIL'}  {name:<44} {mean_tps:>9.4f} TPS  "
              f"sigma {relative * 100:>5.2f}%")
    print("=" * 60)

    if failures:
        print(f"[GATE] {failures} model(s) did not certify.")
        return 1
    print(f"[GATE] All {len(results)} model(s) certified.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
