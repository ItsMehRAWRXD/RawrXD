#!/usr/bin/env python3
"""Measured Ollama REAP16 vs FULL peer ratios. INVENT_PASS=0."""
from __future__ import annotations

import json
import os
from datetime import datetime

ev = r"G:\~dev\rawrxd\evidence\REAP_STRATA_UNSLOTH_OLLAMA_BENCH_001"
od = os.path.join(ev, "ollama")

pairs = [
    ("Qwen3_6-35B-A3B", "reap16-qwen3_6-35b.json", "qwen36-reference-local_latest.json"),
    ("ornith-1_5-35b", "reap16-ornith-1_5.json", "ornith-1.5_35b.json"),
    ("laguna-s-2_1", "reap16-laguna-s-2_1.json", "laguna-s-2.1_Q4_K_M.json"),
    ("nemotron-3_5", "reap16-nemotron-3_5.json", "nemotron-3.5-lightning_30b.json"),
]


def tps(o: dict):
    ed = float(o.get("eval_duration") or 0)
    ec = float(o.get("eval_count") or 0)
    if ed <= 0 or ec <= 0:
        return None, int(ec), int(ed)
    return ec / (ed / 1e9), int(ec), int(ed)


rows = ["Stratum,REAP_tps,REAP_eval,PEER_tps,PEER_eval,RATIO_REAP_over_PEER,EQUAL_EVAL,Disposition,Notes"]
for name, rf, pf in pairs:
    rp, pp = os.path.join(od, rf), os.path.join(od, pf)
    if not os.path.isfile(rp):
        rows.append(f"{name},,,,, ,0,NOT_RUN,missing_reap_json")
        continue
    a = json.load(open(rp, encoding="utf-8"))
    rt, rec, _ = tps(a)
    if "error" in a and not rt:
        rows.append(f"{name},0,0,,,,0,FAIL,reap_error")
        continue
    if not os.path.isfile(pp):
        rows.append(f"{name},{rt},{rec},,, ,0,UNPAIRED,missing_peer_json")
        continue
    b = json.load(open(pp, encoding="utf-8"))
    pt, pec, _ = tps(b)
    if not rt or not pt:
        rows.append(f"{name},{rt},{rec},{pt},{pec},,0,FAIL,missing_tps")
        continue
    ratio = rt / pt
    equal = int(rec == pec and rec > 0)
    notes = []
    if not equal:
        notes.append(f"eval_mismatch REAP={rec} PEER={pec}")
    if pec < 32:
        notes.append("peer_short_eval")
    # fail-closed: do not claim competitive PASS from ratio alone
    disp = "MEASURED_PAIR"
    if not equal:
        disp = "MEASURED_PAIR_CAVEAT"
    rows.append(
        f"{name},{rt:.6f},{rec},{pt:.6f},{pec},{ratio:.6f},{equal},{disp},{';'.join(notes)}"
    )

out = os.path.join(ev, "H2H_RATIOS.csv")
with open(out, "w", encoding="ascii", newline="\n") as f:
    f.write("\n".join(rows) + "\n")
print(f"ASOF={datetime.now().isoformat(timespec='seconds')}")
print(f"WROTE={out}")
for r in rows:
    print(r)
