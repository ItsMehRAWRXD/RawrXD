# Moves 1 → COMPLETE — Master Disposition Matrix

```text
PACK=MOVES_1_COMPLETE_001
ASOF_LOCAL=2026-11-14T09:40:00-05:00
PROMOTE=0 CERTIFIED=0 ENTERPRISE=0/128
GATE_STOP=1 TIP_CLIMB=HOLD
INVENT_PASS=0 NOT_RUN!=PASS CROSS_SHA_CREDIT=0
COMPLETE=0
```

Fail-closed: `SOURCE_WIRED ≠ RUNTIME_REACHED ≠ TOKEN_SURVIVED ≠ PERFORMANCE_PASS`. Do not invent PASS. Do not transfer PASS across SHA.

---

## COMPLETE gate checklist

| Gate | Required | Measured | Hold |
|------|----------|----------|------|
| MOVES_1_35 | DISPOSITION_SEALED | DISPOSITION_SEALED | yes |
| MOVES_36_50 | CLOSED | CLOSED | yes |
| FORCED_AGENT_LOOP | PASS | PASS (Move 50 FORCE_TOOL) | yes |
| MODEL_SELECTED_AGENT | PASS | **FAIL** | **no** |
| Q6K_VULKAN_SPV_REPAIR | OPEN (honest) | OPEN | yes (must stay OPEN) |
| GATE_STOP | 1 | 1 | yes |
| TIP_CLIMB | HOLD | HOLD | yes |
| PROMOTE | 0 | 0 | yes |
| CERTIFIED | 0 | 0 | yes |
| ENTERPRISE | 0/128 | 0/128 | yes |
| **COMPLETE** | 1 iff MODEL_SELECTED=PASS | **0** | — |

`COMPLETE=1` blocked solely by `MODEL_SELECTED_AGENT=FAIL` under current seals.

---

## Moves 1–35 (PERF) — SSOT

**Pack:** `evidence/PERF_MOVES_1_35_IMMEDIATE_001/`  
**Authority:** `evidence/RAWRXD_PERFORMANCE_001/PERF_COMPLETION_CONTRACT.md` §§1–35  
**Status:** `DISPOSITION_SEALED` under `GATE_STOP=1`

| Item | Value |
|------|-------|
| SEARCH_BASELINE_TPS | 4.329 installed |
| MEASURED_UNIQUE | 18 (MANIFEST / COMPLETE_002 SSOT) |
| climb | STOPPED (`NEXT_SPEND=NONE`) |
| 5.904 | HISTORICAL_ONLY |
| TIP_CLIMB | HOLD |
| PROMOTE | 0 |
| §36 Scoreboard | OUT_OF_SCOPE |

Per-move table: `PERF_MOVES_1_35_IMMEDIATE_001/DISPOSITION_MATRIX.md` (do not reopen).

Legal under STOP: disposition/docs only. Forbidden: rainbow live search, tip climb, QB/KVA/LOGITS/SX/5.904 reopen.

---

## Moves 36–50 (CLI numerical) — SSOT

**Pack:** `evidence/CLI_NUMERICAL_MOVES_36_50_001/`  
**Status:** `CLOSED` on product SHA only

| Item | Value |
|------|-------|
| FROZEN_BASELINE (diag) | 0E53D810… (never PASS after rebuild drift) |
| PRODUCT_FIX_SHA | 9797521CEB517B92AC52C518FB2BDB783628ABEA59366DFBE6E784C1A72951A3 |
| Pins | `build_ninja/bin/rawr.exe` + `rawr_FIX_Q6K_HOST_9797521C.exe` MATCH |
| FIRST_NONFINITE | L0 `v_proj` Q6_K via `gemv_q6k.spv` NaN |
| ROOT_SUBCLASS | VULKAN_PACKED_Q6K_GEMV_SPV_NONFINITE |
| Fix | host Q6×Q8_K GEMV (hybrid; SPV still OPEN) |
| Coherence | `Yes, 2 + 2 =` solo+multi; GENERATED_TOKENS=8; FORWARD_FAIL=0 |
| Move 50 | FORCE_TOOL agent PASS; MODEL_SELECTED_TOOL=0 |
| FORWARD_FAIL source | landed earlier (`436c15f81a`); ≠ numerical repair claim |

| Move | Status |
|-----:|--------|
| 36–45 | CLOSED (freeze → V-path subclass) |
| 46–47 | CLOSED (host Q6 route + rebuild 9797521C) |
| 48–49 | CLOSED (coherence measured on NEW SHA) |
| 50 | CLOSED PASS (FORCE_TOOL harness) |

---

## MODEL_SELECTED unforced agent

**Pack:** `evidence/CLI_AGENT_MODEL_SELECTED_001/`  
**Disposition:** `FAIL` (honest)

| Criterion | Result |
|-----------|--------|
| SHA 9797521C only | SHA_MATCH=1 |
| No RAWR_AGENT_FORCE_TOOL | ABSENT |
| MODEL_LOADED=1 | 1 |
| MODEL_SELECTED_TOOL=1 | **0** |
| tool exec + observation | DETERMINISTIC_TOOL_READ fallback only (≠ model-selected) |
| verifiable task close | EXIT=-1; parse FAIL (no JSON `"tool"` key) |

Blocker: TinyLlama does not emit tool-JSON → `MODEL_SELECTED_TOOL` never arms.  
Next owner: `MODEL_SELECTED_AGENT` (tool-schema compliance or stronger instruct model on same SHA).

---

## Next: Move 51+ or COMPLETE

| Path | When |
|------|------|
| COMPLETE=1 | Only after MODEL_SELECTED_AGENT=PASS on 9797521C, unforced |
| Move 51+ | Optional product ladder after COMPLETE gate; not authorized to invent PASS |
| Q6K_VULKAN_SPV_REPAIR | Remains OPEN; host hybrid ≠ SPV fixed |
| REAP_LAGUNA | LEFT_OPEN (capacity; unrelated to COMPLETE flag) |
| 8 TPS climb | FORBIDDEN while GATE_STOP=1 |

---

## Pins / authority flags (frozen)

```text
PRODUCT_SHA=9797521CEB517B92AC52C518FB2BDB783628ABEA59366DFBE6E784C1A72951A3
GATE_STOP=1
TIP_CLIMB=HOLD
PROMOTE=0
CERTIFIED=0
ENTERPRISE=0/128
Q6K_VULKAN_SPV_REPAIR=OPEN
COMPLETE=0
NEXT_OWNER=MODEL_SELECTED_AGENT
```
