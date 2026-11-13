# CLI Top-25 valuation scoreboard (fail-closed)

**ASOF:** 2026-11-13T17:32 · **PROMOTE=0** · **CERTIFIED=0** · **READY_FOR_PEER=0** · **CLI_COMPLETE=0** · **CLI_MATURITY_COMPLETE=0**  
**NOT 100%** · Dense GPU canary PASS (r17) · zip/help EXIT=0 · agent status EXIT=0 · chat GEN OPEN · Competitive TPS sealed MATCH=0

| Axis | Result | Witness | Next gate |
|------|--------|---------|-----------|
| A1 Install + verify | **PASS** (local) | `runs/zip_help_r13` EXIT=0 | clean-VM |
| A2 Agent lifecycle | **PARTIAL** | `runs/agent_status_r13` EXIT=0; chat GEN OPEN | tip chat oneshot GEN>0 |
| A3 Terminal | **PASS** (cited) | COMPETITIVE_BENCH_001 terminal_gate v5 | — |
| A4 Editor/tools CLI | **PARTIAL** | list/paths OK; Deep `/api` NOT_REACHABLE | `/api` or OUT_OF_SCOPE |
| A5a GPU TinyLlama canary | **PASS** | `gpu/tiny_dense_r17` GEN=8 HOST_DECODE=0 TPS=0.998 | — |
| A5a MATCH vs llama | **FAIL** (sealed) | `match/MATCH_STATUS.txt` | GPU_VS_REF_ROOTCAUSE |
| A5b gemma3-1b | **OPEN** | TOKEN_SURVIVED=0 | tokens>0 |
| A5c unlock-125M | **PASS** (GPU) | `gpu/unlock125_r2.*` | quality/MATCH optional |
| A6 Recovery | **PARTIAL** | bad-model EXIT=-1 | resume E2E |
| A7 Docs/dist zip | **PARTIAL** | product channel rawr.exe + help EXIT=0; draft zips still RAWR_EXE_COUNT=0 | CLEAN_VM / publish honesty |
| A8 Competitive H2H | **PARTIAL** | TPS sealed; MATCH=0 ⇒ COMPETITIVE_PASS=0 | MATCH rootcause |
| MoE MiniMax FULL | **HELD** | numerical exclusivity | not this pack |

## Rollup
| Metric | Value |
|--------|-------|
| GPU_DENSE_CANARY | **PASS** (r17) |
| ZIP product channel help | **PASS** EXIT=0 |
| AGENT_STATUS | **PASS** EXIT=0 |
| CHAT_GEN HOST_DECODE=0 | **OPEN** |
| MATCH | **0** |
| CLI_OVERALL_PCT | **51** |
| CLI_MATURITY_COMPLETE | **0** |
| READY_FOR_PEER | **0** |
| PROMOTE | **0** |

`NOT_RUN!=PASS` · `INVENT_PASS=0` · no 100% claim
