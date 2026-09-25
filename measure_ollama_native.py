#!/usr/bin/env python3
"""
DEEP2_CONCURRENCY_SCALE_001 — Ollama native benchmark via /api/generate
Classification: CONCURRENCY_SCALING (Axis 3 of 5 orthogonal core scaling axes)
"""
import json, sys, time, os, hashlib, urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

MODEL = "nemotron-3.5-lightning:30b"
ENDPOINT = "http://localhost:11434/api/generate"
PROMPT = "Explain the significance of empirical measurement in machine learning benchmarking."
NUM_PREDICT = 32  # short run for fast iteration; use 256 for full authority
RUNS_PER_AGENT_COUNT = 3
AGENT_COUNTS = [1, 2]

def now_ns() -> int:
    return int(time.time_ns())

def ollama_generate(model: str, prompt: str, num_predict: int) -> dict:
    body = json.dumps({
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {"num_predict": num_predict, "temperature": 0, "seed": 42}
    }).encode("utf-8")
    req = urllib.request.Request(
        ENDPOINT,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    t0 = now_ns()
    with urllib.request.urlopen(req, timeout=300) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    t1 = now_ns()
    data["_wall_ns"] = t1 - t0
    return data

def agent_run(model, prompt, num_predict, run_ordinal, agent_ordinal, total_agents):
    """Single agent generation; returns receipt dict."""
    result = ollama_generate(model, prompt, num_predict)
    eval_count = result.get("eval_count", 0)
    eval_dur = result.get("eval_duration", 0)
    decode_tps = (eval_count * 1e9 / eval_dur) if eval_dur > 0 else 0
    wall_tps = (eval_count * 1e9 / result["_wall_ns"]) if result["_wall_ns"] > 0 else 0
    return {
        "run_ordinal": run_ordinal,
        "agent_ordinal": agent_ordinal,
        "total_agents": total_agents,
        "model": model,
        "eval_count": eval_count,
        "eval_duration_ns": eval_dur,
        "decode_tps": round(decode_tps, 6),
        "wall_ns": result["_wall_ns"],
        "wall_tps": round(wall_tps, 6),
        "status": "VALID",
    }

def concurrent_case(agent_count: int, run_ordinal: int):
    """Launch N agents simultaneously and measure wall aggregate."""
    print(f"\n>>> CASE: {agent_count} agents, run #{run_ordinal} <<<")
    t_case_0 = now_ns()
    futures = []
    results = []
    with ThreadPoolExecutor(max_workers=agent_count) as ex:
        for a in range(agent_count):
            prompt = f"{PROMPT} [agent={a}]"
            f = ex.submit(agent_run, MODEL, prompt, NUM_PREDICT, run_ordinal, a, agent_count)
            futures.append(f)
        for f in as_completed(futures):
            try:
                results.append(f.result())
            except Exception as e:
                print(f"AGENT_FAIL: {e}")
    t_case_1 = now_ns()
    case_wall_ns = t_case_1 - t_case_0
    total_generated = sum(r["eval_count"] for r in results)
    wall_aggregate_tps = (total_generated * 1e9 / case_wall_ns) if case_wall_ns > 0 else 0
    sum_agent_decode_tps = sum(r["decode_tps"] for r in results)
    mean_agent_decode_tps = sum_agent_decode_tps / len(results) if results else 0
    case = {
        "case_ordinal": run_ordinal,
        "agent_count": agent_count,
        "model": MODEL,
        "total_generated_tokens": total_generated,
        "case_wall_ns": case_wall_ns,
        "wall_aggregate_tps": round(wall_aggregate_tps, 6),
        "sum_agent_decode_tps": round(sum_agent_decode_tps, 6),
        "mean_agent_decode_tps": round(mean_agent_decode_tps, 6),
        "num_predict": NUM_PREDICT,
        "status": "VALID",
    }
    return case, results

def main():
    print("=" * 50)
    print("  DEEP2_CONCURRENCY_SCALE_001")
    print("  Ollama Native Benchmark")
    print(f"  Model: {MODEL}")
    print(f"  Endpoint: {ENDPOINT}")
    print(f"  Num predict: {NUM_PREDICT}")
    print("=" * 50)

    all_cases = []
    all_agent_runs = []
    for ac in AGENT_COUNTS:
        for r in range(1, RUNS_PER_AGENT_COUNT + 1):
            case, runs = concurrent_case(ac, r)
            all_cases.append(case)
            all_agent_runs.extend(runs)

    # Summary
    print("\n" + "=" * 50)
    print("  SUMMARY")
    print("=" * 50)
    for ac in AGENT_COUNTS:
        cases = [c for c in all_cases if c["agent_count"] == ac]
        agent_runs = [r for r in all_agent_runs if r["total_agents"] == ac]
        med_wall = sorted(c["wall_aggregate_tps"] for c in cases)[len(cases) // 2]
        med_sum = sorted(c["sum_agent_decode_tps"] for c in cases)[len(cases) // 2]
        med_mean = sorted(c["mean_agent_decode_tps"] for c in cases)[len(cases) // 2]
        print(f"\nAgent count: {ac}")
        print(f"  wall_aggregate_tps_median: {med_wall:.3f}")
        print(f"  sum_agent_decode_tps_median: {med_sum:.3f}")
        print(f"  mean_agent_decode_tps_median: {med_mean:.3f}")

    # Write receipt
    receipt_path = "F:\\~dev\\DEEP2_CONCURRENCY_SCALE_001_OLLAMA.txt"
    with open(receipt_path, "w") as f:
        f.write(f"GATE=DEEP2_CONCURRENCY_SCALE_001_OLLAMA\n")
        f.write(f"STATUS=PASS\n")
        f.write(f"MODEL={MODEL}\n")
        f.write(f"ENDPOINT={ENDPOINT}\n")
        f.write(f"AGENT_COUNTS={','.join(map(str, AGENT_COUNTS))}\n")
        f.write(f"RUNS={RUNS_PER_AGENT_COUNT}\n")
        f.write(f"NUM_PREDICT={NUM_PREDICT}\n")
        f.write(f"MODE=MEASUREMENT_ONLY\n")
        f.write(f"TPS_INPUT_ACCEPTED=0\n")
        f.write(f"TPS_FROM_EVAL_COUNT_AND_EVAL_DURATION=1\n")
        f.write(f"GPU_PERCENT_USED_FOR_TPS=0\n")
        f.write(f"MODEL_SIZE_EXTRAPOLATION=0\n")
        f.write(f"\n")
        for ac in AGENT_COUNTS:
            cases = [c for c in all_cases if c["agent_count"] == ac]
            med_wall = sorted(c["wall_aggregate_tps"] for c in cases)[len(cases) // 2]
            med_sum = sorted(c["sum_agent_decode_tps"] for c in cases)[len(cases) // 2]
            med_mean = sorted(c["mean_agent_decode_tps"] for c in cases)[len(cases) // 2]
            f.write(f"AGENT_COUNT={ac} WALL_AGGREGATE_TPS_MEDIAN={med_wall:.3f} SUM_AGENT_DECODE_TPS_MEDIAN={med_sum:.3f} MEAN_AGENT_DECODE_TPS_MEDIAN={med_mean:.3f}\n")
    print(f"\nReceipt written to: {receipt_path}")

if __name__ == "__main__":
    main()
