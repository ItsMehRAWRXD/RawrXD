# COMPETITIVE_BENCH_001 — STATUS

```
ASOF_LOCAL=2026-11-13T14:25-05:00
WORKSTREAM=P3_INDEPENDENT_COMPETITIVE_TESTING
PROMOTE=0
TIP_CLIMB=HOLD
NOT_RUN != PASS
MEASURED=1
INVENTED_WINS=0
GIT_HEAD=1f938bb640f45244f6cfc5356bd64adf38699cbf
BRANCH=feature/ide-agentic-product-path-20261026
```

## Suite matrix (measured this session)

| Suite | Result | Command / path | EXE SHA-256 |
|-------|--------|----------------|-------------|
| terminal_bench | FAIL | `evidence\FOUR_PANEL_COMPLETION_001\bin\terminal_gate.exe` | `5125CFE10FE6C89F649B401A216EA976BC44DB06D44D1EA401E41411D579094D` |
| cli_status | PASS | `bin\SovereignCLI.exe status` | `A390E69F596FBF2A5D9B2CA4F429437D2962AA593310EF9031B2542D804D7E4F` |
| cli_version | PASS | `bin\SovereignCLI.exe version` | (same) |
| cli_validate | PASS | `bin\SovereignCLI.exe validate` → 2/2 | (same) |
| cli_benchmark | PASS | `bin\SovereignCLI.exe benchmark --iter 100` (runner ignored iter; used 10000) | (same) |
| cli_health | PASS | `bin\SovereignCLI_Complete.exe health` | `5BC452BE0E518DC6E9F866A0D57B33A24CC234B165B336ACAF3BA9A5648DA20C` |
| cli_complete_version | PASS | `bin\SovereignCLI_Complete.exe version` | (same) |
| autonomous_cli_list | PASS | `bin\RawrXD_Autonomous_CLI.exe` ← `list`/`quit` | `16B134F6DF56F6DB91AB6367796AD389CFA42D53B658F3B470D4494A72B590BF` |
| ide_bench (presence) | PASS | `Test-Path bin\RawrXD-Win32IDE.exe` + SHA | `D60C6F9A840D6EC824215BAE604EEF2561E5DE844C0F856893BE2E5AF5A0F31C` |
| ide_bench (task suite) | NOT_RUN | No IDE-Bench task fixtures / scoring harness | — |
| coding_task | FAIL | `cl … fixtures\agent_multierror_calc\*.cpp` (intentional broken fixture) | — |
| game_dev | NOT_RUN | No game-dev fixtures under `fixtures/` | — |
| reverse_cli | FAIL | `bin\reverse_cli.exe --help` exit `-1073741515` (DLL load fail) | — |
| slingshot_bench | FAIL | `bin\slingshot_bench.exe --help` exit `-1073741515` | — |

## Scores (only if measured)

Competitive leaderboard / parity %: **not measured** (prior provisional scorecards elsewhere are planning-only; not reused as PASS).

Kernel microbench (SovereignCLI, measured):

- RMSNorm: 0.003 us/call, 9844.38 GB/s (10000 iters, 4096 elems)
- ResidualAdd: 0.674 us/call
- LayerNorm / Q4K: SKIPPED by binary

Terminal gate subchecks (measured, overall FAIL):

- PASS: echo capture marker_in_pipe, interrupt, resize, restart, capture after restart, no orphan, PowerShell capture
- FAIL: compile+run via ConPTY
- `TERMINAL=FAIL_CLOSED` `fail_count=1` `exit=1`

Coding fixture: `cl` compile exit=2 (syntax / missing `sub` / iostream) — fixture designed for agent autofix; **not** a competitive win.

## Harness

- Absent named IDE-Bench / Terminal-Bench / coding-task competitive suites in-tree.
- Wired minimal runner: `benchmarks/competitive/Run-CompetitiveBench.ps1` (invokes real entrypoints; no fake scores).
- Logs: `evidence/COMPETITIVE_BENCH_001/logs/`

## Laws

`SOURCE_WIRED != RUNTIME_REACHED != TOKEN_SURVIVED != PERFORMANCE_PASS`  
`PROMOTE=0` · no invented benchmark wins.
