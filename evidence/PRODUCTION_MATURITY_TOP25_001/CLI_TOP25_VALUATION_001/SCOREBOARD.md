# CLI Top-25 valuation scoreboard (fail-closed)

**ASOF:** 2026-11-13 · **PROMOTE=0** · **CERTIFIED=0** · **CROSS_SHA_CREDIT=0** · **TIP_CLIMB=HOLD**  
**CLI_VALUATION=MEASURED_PARTIAL** · **READY_FOR_PEER=0** · **CLI_COMPLETE=0** · **CLI_OVERALL_PCT=58**

Peer axes ≈ Cursor / VS Code+Copilot / Continue — CLI/`rawr.exe`/headless/Deep `/api` only. GUI HWND out of scope.

| Axis | Result | Witness | Next gate |
|------|--------|---------|-----------|
| A1 Install + verify | **PASS** (local) | `runs/install_verify.*` | clean-VM zip with product `rawr.exe` |
| A2 Agent lifecycle | **OPEN** | `runs/agent_status.exit.txt` TIMEOUT | non-hang `rawr agent status` EXIT=0 |
| A3 Terminal | **PASS** | COMPETITIVE_BENCH_001 terminal_gate v5 | optional external Terminal-Bench |
| A4 Editor/tools (CLI) | **PARTIAL** | `list`/`paths` OK; Deep `/api` NOT_REACHABLE | `/api/tool` live or OUT_OF_SCOPE |
| A5a GPU TinyLlama | **PASS** (canary) | `gpu/tiny_gpu*` HOST_DECODE=0 tokens=8 | MATCH + Top-25 TPS |
| A5b GPU gemma3-1b | **OPEN** | `gpu/gemma3_gpu.*` TOKEN_SURVIVED=0 | tokens>0 CLEAN_EXIT |
| A5c unlock-125M | **OPEN** | fixture GGUF missing | resolve + GPU canary |
| A6 Recovery | **PARTIAL** | bad-model EXIT=-1 | resume E2E |
| A7 Docs/dist | **PARTIAL** | INSTALL + DRAFT_SHA; NOT_PUBLISHED | publish/clean-VM |
| A8 Competitive | **PARTIAL** | terminal PASS; H2H NOT_SEALED | GPU H2H seal/HOLD |
| MoE MiniMax FULL | **HELD** | numerical exclusivity | not this pack |

## Rollup
| Metric | Value |
|--------|-------|
| CLI_OVERALL_PCT | **58** (`VALUATION_CLI.txt`) |
| GPU_DENSE_CANARY | **PASS** |
| HOST_DECODE as GPU | **INVALID** |
| READY_FOR_PEER | **0** |
| COMPETITIVE_PASS | **0** |
| PROMOTE | **0** |

`NOT_RUN!=PASS` · `INVENT_PASS=0`
