# COMPETITIVE_BENCH_001 — Suite matrix

ASOF_LOCAL=2026-11-13T14:50:45-05:00  
WORKSPACE=`g:\~dev\rawrxd`  
RUN=logs/run_competitive_bench_20261113_145044.*  
PROMOTE=0 · TIP_CLIMB=HOLD · NOT_RUN ≠ PASS · no invented scores · COMPETITIVE_PASS=0

Named upstream **IDE-Bench / Terminal-Bench** packages remain **NOT_IN_TREE**. Stubs under `harness/` + `benchmarks/competitive/Run-CompetitiveBench.ps1` invoke real CLI/IDE/terminal entrypoints. MiniMax QC EXCLUSIVE lock held — no MoE/giant loads this turn.

| Suite | Entrypoint | Command | SHA-256 (exe) | Disposition | Score / note |
|-------|------------|---------|---------------|-------------|--------------|
| Terminal-Bench stub→terminal_gate | `evidence/FOUR_PANEL_COMPLETION_001/bin/terminal_gate.exe` | `terminal_gate.exe` | `30DBF28C7280CF080F3C5D6C527969007C86E8D3FBCEAE9DC08840B4529B2D1B` | **PASS** (stdout fail_count=0; ConPTY compile+run PASS) | not peer-scored |
| IDE-Bench (presence) | `bin/RawrXD-Win32IDE.exe` | presence + SHA | `D60C6F9A840D6EC824215BAE604EEF2561E5DE844C0F856893BE2E5AF5A0F31C` | **PRESENCE_OK** / PARTIAL | GUI_E2E=NOT_RUN |
| IDE --help smoke | same | `--help` timeout 5s | same | **FAIL** (TIMEOUT) | no CLI help contract |
| CLI kernel status | `bin/SovereignCLI.exe` | `status` | `A390E69F596FBF2A5D9B2CA4F429437D2962AA593310EF9031B2542D804D7E4F` | **PASS** (9/9 kernels) | content |
| CLI kernel validate | same | `validate` | same | **FAIL** (1/2; RMSNorm FAIL) | ResidualAdd PASS |
| CLI kernel benchmark | same | `benchmark --iter 100` | same | **PARTIAL** (RMSNorm+ResidualAdd timed; LayerNorm+Q4K SKIPPED) | RMSNorm 0.004 µs/call / 8477.11 GB/s; ResidualAdd 0.365 µs/call |
| CLI health | `bin/SovereignCLI_Complete.exe` | `health` | `5BC452BE0E518DC6E9F866A0D57B33A24CC234B165B336ACAF3BA9A5648DA20C` | **PASS** (Quick Test PASSED) | ≠ Top-25 |
| Coding-task fixture | `fixtures/agent_multierror_calc` | `cl ...` via vcvars64 | n/a | **FAIL** (intentional multi-error; agent autofix NOT_RUN) | exit=2 |
| Game-dev competitive | — | — | — | **NOT_RUN** (no fixtures) | — |
| External IDE-Bench package | — | — | — | **NOT_RUN** / NOT_IN_TREE | — |
| External Terminal-Bench package | — | — | — | **NOT_RUN** / NOT_IN_TREE | — |
| SWE-bench real-agent | `RawrXD-SWEBench.exe` | live model | — | **NOT_RUN** | null-agent prior 0.0% ≠ competitive PASS |
| Ollama / vLLM / llama.cpp H2H | — | — | — | **NOT_RUN** | HEAD_TO_HEAD=NOT_SEALED |

## Harness

- `benchmarks/competitive/Run-CompetitiveBench.ps1` (ExitCode Refresh poll added 2026-11-13)
- `harness/Run-TerminalBench.ps1` · `Run-IdeBench.ps1` · `Run-CodingTaskBench.ps1` · `Run-CliKernelBench.ps1`

## Authority

- Detail: `STATUS.txt` · `OPEN_CONPTY_COMPILE_RUN.md` · `EXE_SHA256.txt`
- Recognition: `PRODUCTION_MATURITY_TOP25_001` (TOP25_RECOGNITION=NOT_READY)
