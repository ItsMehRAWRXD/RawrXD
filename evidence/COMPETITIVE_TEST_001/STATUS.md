# COMPETITIVE_TEST_001 — STATUS

```
ASOF_UTC=2026-11-13T19:35:47Z
PROMOTE=0
CERTIFIED=0
TIP_CLIMB=HOLD
NOT_RUN!=PASS
NO_INVENT_SCORES=1
MINIMAX_FULL=FORBIDDEN
QUALITY_CURVE=FORBIDDEN
```

## Suite matrix (this landing)

| Suite | Maps to | Status | Score | Notes |
| --- | --- | --- | --- | --- |
| IDE_BENCH_PROXY | IDE-Bench (local) | **FAIL** | NOT_SCORED | `Smoke-IDE-TurnKey.ps1` runs; fails source parity: tool-role label color + agentic route symbols missing in tip sources |
| TERMINAL_BENCH_PROXY | Terminal-Bench (local) | **FAIL** | NOT_SCORED | `terminal_gate.exe` fail_count=1 (`compile+run via ConPTY`); other assertions PASS; FAIL_CLOSED even with vcvars64 |
| CODING_TASK_SWEBENCH | coding-task suite | **MEASURED_ZERO** | **0.0%** overall | `RawrXD-SWEBench.exe` null-agent self-test on seed4 (4/4 empty patch). Exit 0. **Not** a competitive agent score |
| GAME_DEV_SUNSHINEFPS | real game-dev fixture | **NOT_RUN** | none | PE x64 present (`SHA256=0E3A76A6…`); OS rejects launch (“cannot be run in Win32 mode”). `demo_project/project.json` present |

Authoritative machine-readable: `MATRIX.json` (and `runs/MATRIX_20261113_143547.json`).

## Harness wired this landing

- `evidence/COMPETITIVE_TEST_001/harness/Run-CompetitiveTestSmoke.ps1`
- `evidence/COMPETITIVE_TEST_001/LAW.txt`
- Fix: `scripts/Run-TurnkeyIdeSmoke.ps1` angle-bracket envHints broke PS5.1 parse (`<` redirection) — removed so IDE proxy can execute

## Explicit non-claims

- No public IDE-Bench / Terminal-Bench leaderboard scores claimed.
- Null-agent 0.0% ≠ competitive coding PASS.
- Historical `FOUR_PANEL_COMPLETION_001/TERMINAL_GATE.md` TERMINAL=PASS is prior sealed evidence; **this** re-run is FAIL_CLOSED on compile+run.
- SunshineFPS fixture inventory ≠ gameplay suite PASS.
- `--real-agent` SWEBench / MiniMax FULL / QUALITY_CURVE **not run** (host exclusivity).

## OPEN

1. IDE parity symbols/colors in Win32 chat renderer + Win32IDE agentic route glue.
2. terminal_gate ConPTY compile+run assertion (MSVC/toolchain path inside ConPTY session).
3. SWEBench `--real-agent` on non-MiniMax host-safe model (or deferred until Numerical exclusivity lifts).
4. Rebuild/relink SunshineFPS to a host-runnable PE; seal a real gameplay scoring suite.
5. Import/adapt true external IDE-Bench / Terminal-Bench if licensed fixtures are added.
