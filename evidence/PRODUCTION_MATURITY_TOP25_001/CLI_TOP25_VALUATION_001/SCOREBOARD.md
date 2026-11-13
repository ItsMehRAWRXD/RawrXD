# CLI_TOP25_VALUATION_001 — axis scoreboard

**ASOF:** 2026-11-13 · **PROMOTE=0** · **CERTIFIED=0** · **READY_FOR_PEER=0** · **TIP_CLIMB=HOLD**

EXE_SHA256 (r2): `3857FC27A48058756244E5A8938275F2EE1B19E2442AF330D734382D7D90C520`

| Axis | Status | Evidence | Notes |
|------|--------|----------|-------|
| A1 Install / verify | **PASS** (local help) | `runs/install_verify.*` | ≠ ship/clean-VM |
| A2 Agent lifecycle | **OPEN** | `runs/agent_status.exit.txt=TIMEOUT` | serve TIMEOUT |
| A3 Terminal | **PASS** (cited) | COMPETITIVE_BENCH_001 terminal_gate v5 | External Terminal-Bench NOT_IN_TREE |
| A4 Editor / tools (CLI) | **PARTIAL** | `list` OK; `tools --help` EXIT=1 usage | HWND out of CLI scope |
| A5 GPU decode TinyLlama | **PASS** canary | `gpu/tiny_gpu_r2.*` TOKEN_SURVIVED=8 HOST_DECODE=0 | TPS/MATCH Top-25 OPEN |
| A5b GPU gemma3-1b | **OPEN** | `gpu/gemma3_gpu.*` TOKEN_SURVIVED=0 | |
| A5c unlock-125M | **OPEN** | fixture GGUF missing | |
| A6 Recovery | **PARTIAL** | bad-model EXIT=-1 | agent recovery hang |
| A7 Docs / dist honesty | **PARTIAL** | INSTALL.md + DRAFT_SHA; ZIP_EXE_ABSENT | NOT_PUBLISHED |
| A8 Competitive harness | **PARTIAL** | terminal PASS; cli_validate FAIL; H2H NOT_SEALED | |

## Rollup
`CLI_OVERALL_PCT=46` (mean of VALUATION_CLI categories) · `CLI_MATURITY_COMPLETE=0` · `HOST_DECODE≠PASS`

## Explicit non-claims
Not Top-25 ranked · Not READY_FOR_PEER · Not PROMOTE · gemma3 not sealed · MiniMax FULL not run
