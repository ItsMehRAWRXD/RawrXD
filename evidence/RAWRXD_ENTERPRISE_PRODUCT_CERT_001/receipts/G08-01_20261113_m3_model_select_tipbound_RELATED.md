# G08-01 RELATED — M3 MODEL_SELECTED_TOOL tipbound diagnose (30DCB4B1)

ASOF=2026-11-13T23:09:11-05:00  
RESULT=RELATED / MODEL_SELECTED_TOOL=0  
PROMOTE=0 · INVENT_PASS=0 · CROSS_SHA_CREDIT=0 · NOT_RUN≠PASS

## Diagnosis (why model-select=0 while FORCE_TOOL PASS)

| Path | Behavior |
|------|----------|
| FORCE_TOOL (G05-06) | `RAWR_AGENT_FORCE_TOOL` set → `skip_model_load=1` → never calls `modelDecideTool` → EBT PASS on force-path **only**; MODEL_SELECTED_TOOL stays 0 by design |
| MODEL_SELECTED (this) | FORCE absent → TinyLlama loads → agent-decide prefills `{"tool":` then emits `<unk>×N` → `parseToolDecision` FAIL → deterministic read fallback ≠ MODEL_SELECTED_TOOL |

Root cause (non-Deep2 surface): `rawr_agent_executor.hpp::modelDecideTool` assistant partial JSON prefill + TinyLlama chat continuation → unk streak (prior G08-01 20261113_222135 confirmed output=`{"tool":<unk>…}`).

## Measured remasure (pin 30DCB4B1 RO)

| Field | Value |
|-------|-------|
| EXE | `build_ninja/bin/rawr_gpufwd_30DCB4B1.exe` |
| EXE_SHA256 | `30DCB4B12DCA0F13542C14CCC6C4038E70DBFE2555DE65AB005093A1FF60F24D` |
| HASH_MATCH | 1 |
| COMMAND | `agent tinyllama --workspace <…/m3_model_select_30dcb4_diag_20261113_230900/ws> --auto=full --max-tokens 32` |
| ENV | `RAWR_AGENT_FORCE_TOOL` ABSENT |
| WALL_MS | 91592 (killed) |
| MODEL_LOADED | 1 |
| PARSE_FAILED | 1 |
| UNK_SEEN | 1 |
| MODEL_SELECTED_TOOL | **0** (final diag line absent due to kill; prior seal + parse/unk evidence) |

## Minimal non-Deep2 wire (private cand SOURCE_WIRED)

- File: `src/cli/rawr_agent_executor.hpp` — remove `{"tool":` prefill; add unk-streak abort (NO_JSON_PREFILL=1).
- Tip EXE / CLI pin RO: **not** rebuilt.
- Private cand rebuild **blocked**: concurrent P0 `Deep2Engine.h` C2535 `repairModelLoadedFromRoots` duplicate (owned by other workers; not edited here).
- SOURCE_WIRED=1 · RUNTIME_REACHED=0 · TOKEN_SURVIVED=0 · INVENT_PASS=0

## Artifacts

- `receipts/m3_model_select_30dcb4_diag_20261113_230900/run.meta.txt`
- `receipts/m3_model_select_30dcb4_diag_20261113_230900/run.err.witness.txt` (trimmed; unk + TOOL_FORCE=1 prefill)
- Prior: `receipts/G08-01_20261113_m3_model_select_30dcb4.md` / `m3_model_select_30dcb4_20261113_222135/`
