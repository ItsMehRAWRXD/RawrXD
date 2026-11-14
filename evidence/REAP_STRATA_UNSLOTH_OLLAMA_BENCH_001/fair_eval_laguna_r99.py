"""Fair same-eval_count Laguna REAP vs peer. Document both if peer cannot hit 32."""
from __future__ import annotations

import json
import math
import subprocess
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path

EV = Path(r"G:\~dev\rawrxd\evidence\REAP_STRATA_UNSLOTH_OLLAMA_BENCH_001")
OL = EV / "ollama"
OL.mkdir(parents=True, exist_ok=True)
PROMPT = "Say hi in one short sentence."
REAP_TAG = "reap16-laguna-s-2_1"
PEER_TAG = "laguna-s-2.1:Q4_K_M"


def bench(tag: str, num_predict: int, suffix: str) -> dict:
    body = {
        "model": tag,
        "prompt": PROMPT,
        "stream": False,
        "options": {"num_predict": num_predict, "temperature": 0},
    }
    body_path = OL / f"fair_r99_{suffix}_body.json"
    out_path = OL / f"fair_r99_{suffix}.json"
    err_path = OL / f"fair_r99_{suffix}.curl.err"
    body_path.write_text(json.dumps(body, separators=(",", ":")), encoding="utf-8")
    t0 = time.time()
    r = subprocess.run(
        [
            "curl.exe", "-sS", "--max-time", "1800",
            "-H", "Content-Type: application/json",
            "--data-binary", f"@{body_path}",
            "http://127.0.0.1:11434/api/generate",
            "-o", str(out_path),
        ],
        capture_output=True, text=True,
    )
    wall_ms = int((time.time() - t0) * 1000)
    if err_path:
        err_path.write_text(r.stderr or "", encoding="utf-8")
    row = {
        "tag": tag,
        "num_predict": num_predict,
        "eval_count": 0,
        "eval_duration_ns": 0,
        "tok_per_s": 0.0,
        "done": False,
        "wall_ms": wall_ms,
        "http_ok": False,
        "log": str(out_path),
    }
    try:
        if out_path.exists() and out_path.stat().st_size > 10:
            j = json.loads(out_path.read_text(encoding="utf-8"))
            eval_count = int(j.get("eval_count") or 0)
            ens = int(j.get("eval_duration") or 0)
            tps = round((eval_count * 1e9) / ens, 3) if ens > 0 else 0.0
            row.update({
                "eval_count": eval_count,
                "eval_duration_ns": ens,
                "tok_per_s": tps,
                "done": bool(j.get("done")),
                "http_ok": bool(j.get("done")) and eval_count > 0,
            })
    except Exception as ex:
        row["parse_error"] = str(ex)
    return row


def main() -> None:
    # Match prior REAP eval_count=32 path, then try peer at 32 and at 11.
    reap32 = bench(REAP_TAG, 32, "laguna_reap_np32")
    peer32 = bench(PEER_TAG, 32, "laguna_peer_np32")
    peer11 = bench(PEER_TAG, 11, "laguna_peer_np11")

    ratios = {}
    if reap32["http_ok"] and peer32["http_ok"] and peer32["tok_per_s"] > 0:
        ratios["reap_vs_peer_np32"] = {
            "equal_eval": int(reap32["eval_count"] == peer32["eval_count"]),
            "reap_eval": reap32["eval_count"],
            "peer_eval": peer32["eval_count"],
            "ratio": round(reap32["tok_per_s"] / peer32["tok_per_s"], 6) if peer32["tok_per_s"] else None,
            "workload_equivalent": int(reap32["eval_count"] == peer32["eval_count"] and reap32["eval_count"] > 0),
        }
    if reap32["http_ok"] and peer11["http_ok"] and peer11["tok_per_s"] > 0:
        ratios["reap32_vs_peer11_naive"] = {
            "equal_eval": int(reap32["eval_count"] == peer11["eval_count"]),
            "reap_eval": reap32["eval_count"],
            "peer_eval": peer11["eval_count"],
            "ratio": round(reap32["tok_per_s"] / peer11["tok_per_s"], 6) if peer11["tok_per_s"] else None,
            "workload_equivalent": int(reap32["eval_count"] == peer11["eval_count"]),
            "note": "naive only if eval mismatch; do not invent 9.7x PASS",
        }

    # Prefer equal-eval measured x; else OPEN
    measured_x = "OPEN"
    reason = "no equal-eval_count REAP/peer H2H this run"
    for key in ("reap_vs_peer_np32",):
        r = ratios.get(key)
        if r and r.get("workload_equivalent") == 1 and r.get("ratio") is not None:
            measured_x = f"{r['ratio']:.6f}x"
            reason = f"equal_eval={r['reap_eval']} via {key}"
            break

    tz = timezone(timedelta(hours=-5))
    asof = datetime.now(tz).strftime("%Y-%m-%dT%H:%M:%S%z")
    asof = asof[:-2] + ":" + asof[-2:]
    out = {
        "ASOF_LOCAL": asof,
        "PROMOTE": 0,
        "TIP_CLIMB": "HOLD",
        "INVENT_PASS": 0,
        "PERFORMANCE_PASS": 0,
        "NO_INVENT_9_7X": 1,
        "REAP": reap32,
        "PEER_NP32": peer32,
        "PEER_NP11": peer11,
        "RATIOS": ratios,
        "REAP_measured_x_or_OPEN": measured_x,
        "REASON": reason,
    }
    path = EV / "FAIR_EVAL_LAGUNA_R99.json"
    path.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(json.dumps(out, indent=2))
    print(f"WROTE {path}")


if __name__ == "__main__":
    main()
