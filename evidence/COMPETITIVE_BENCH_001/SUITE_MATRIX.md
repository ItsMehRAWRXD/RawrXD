# COMPETITIVE_BENCH_001 — Suite matrix

ASOF_LOCAL=2026-11-13T14:25-05:00  
WORKSPACE=`g:\~dev\rawrxd`  
GIT_HEAD_AT_SEAL=`1f938bb640f45244f6cfc5356bd64adf38699cbf` (pre-commit tip)  
PROMOTE=0 · TIP_CLIMB=HOLD · NOT_RUN ≠ PASS · no invented scores

Named upstream **IDE-Bench / Terminal-Bench** suites were **absent**; minimal stubs under `harness/` invoke real CLI/IDE entrypoints.

| Suite | Entrypoint | Command | SHA-256 (exe) | Result | Score |
|-------|------------|---------|---------------|--------|-------|
| Terminal-Bench (stub→terminal_gate) | `evidence/FOUR_PANEL_COMPLETION_001/bin/terminal_gate.exe` | `terminal_gate.exe` | `5125CFE10FE6C89F649B401A216EA976BC44DB06D44D1EA401E41411D579094D` | **FAIL_CLOSED** (fail_count=1: compile+run via ConPTY) | not scored |
| IDE-Bench (presence) | `bin/RawrXD-Win32IDE.exe` | presence + SHA; GUI E2E NOT_RUN | `D60C6F9A840D6EC824215BAE604EEF2561E5DE844C0F856893BE2E5AF5A0F31C` | **PASS** (binary present); GUI_E2E=**NOT_RUN** | not scored |
| CLI kernel validate | `bin/SovereignCLI.exe` | `SovereignCLI.exe validate` | `A390E69F596FBF2A5D9B2CA4F429437D2962AA593310EF9031B2542D804D7E4F` | **PASS** 2/2 (RMSNorm, ResidualAdd) exit=0 | 2/2 measured |
| CLI kernel benchmark | `bin/SovereignCLI.exe` | `SovereignCLI.exe benchmark --iter 100` | same | **PASS** exit=0; LayerNorm+Q4K **SKIPPED** | RMSNorm 0.003 µs/call / 9844.38 GB/s; ResidualAdd 0.674 µs/call |
| CLI kernel status/version | `bin/SovereignCLI.exe` | `status` / `version` | same | **PASS** exit=0 | n/a |
| Autonomous CLI list | `bin/RawrXD_Autonomous_CLI.exe` | stdin `list`/`quit` | `16B134F6DF56F6DB91AB6367796AD389CFA42D53B658F3B470D4494A72B590BF` | **PASS** exit=0; 6/69 compilers available | 6/69 ready (measured) |
| Coding-task fixture | `fixtures/agent_multierror_calc` | `cl ... add.cpp mul.cpp main.cpp` (via vcvars64) | n/a (sources) | **FAIL** exit=2 (intentional multi-error fixture; not agent-autofix run) | not scored |
| Game-dev competitive | — | — | — | **NOT_RUN** — no game competitive fixtures (`fixtures/game` absent; unity/unreal dirs are engine bindings, not bench fixtures) | — |

## Harness stubs (wired, real entrypoints)

- `harness/Run-TerminalBench.ps1`
- `harness/Run-IdeBench.ps1`
- `harness/Run-CodingTaskBench.ps1`
- `harness/Run-CliKernelBench.ps1`
