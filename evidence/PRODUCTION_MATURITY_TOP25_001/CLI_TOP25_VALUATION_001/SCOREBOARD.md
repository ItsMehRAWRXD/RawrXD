# CLI Top-25 valuation scoreboard (fail-closed)

**ASOF:** 2026-11-13T20:45 · **TIP=15A119D1…** · **PROMOTE=0** · **CLI_PCT=67** · **CLI_COMPLETE=0**

| Axis | Result | Witness |
|------|--------|---------|
| Tip pin | **15A119D1 GpuFwd** | `bin/rawr_gpufwd_15A119D1.exe` |
| Cat2 docs honesty | **CLOSED 78→85** tertiary HISTORICAL + CLEAN_VM=ABSENT | `runs/cat2_install_docs_R46.meta.txt` / `R46_CAT2_DOCS_HONESTY_CLOSE_SEAL.txt` |
| Cat5 ConPTY host | **CLOSED tip term start +OK** | `runs/term_conpty_R43_20261113_201949.*` / `R43_CAT5_CONPTY_HOST_CLOSE_SEAL.txt` |
| Cat5 tip tail/stop | **CLOSED 4/5** host overlap+mutex+idempotent stop | `runs/term_tail_R45_20261113_203429.meta.txt` / `R45_CAT5_TERM_TAIL_CLOSE_SEAL.txt` |
| Cat4 multiturn depth | **CLOSED chat→resume→resume GEN=4×3** | `runs/agentic_*_R40_20261113_193831.*` |
| Cat7 Dense MATCH | **CLOSED llama32 uncoach** | `R42_CAT7_DENSE_MATCH_CLOSE_SEAL.txt` |
| Cat11 H2H MATCH | **CLOSED** | `R42_CAT11_H2H_MATCH_CLOSE_SEAL.txt` |
| Cat10 stub/missing | **CLOSED** | `CAT10_STUB_MODEL_CLOSED.txt` / `CAT10_MISSING_PATH_CLOSED.txt` |
| Cat4 TOOL/REPL tip | **HELD** FORCE_TOOL ABSENT on tip | `R46_HELD_DISPOSITIONS.txt` |

**Cats raised:** R45 CAT5 78→85 · **R46 CAT2 78→85** docs honesty → CLI floor 67 (SUM 811).  
**Held:** CAT4 TOOL/REPL85 Debugger15 REAP45 MoE58 Terminal-Bench + 1/5 flaky · CLEAN_VM ABSENT.  
**OVERALL=min(67,48)=48** · GUI=48 absorb074 MF · `PROMOTE=0` · `TIP_CLIMB=HOLD`

Open list: `OPEN_REMAINING.txt`
