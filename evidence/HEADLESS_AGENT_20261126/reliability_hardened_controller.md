# Reliability campaign — hardened controller (2026-11-27)

Fresh per-model run with the FULLY hardened controller (per-provider channel profile + text
parser hardening + edit convergence feedback + GUI-run short-circuit). HEAD 5a2391e278.
Backend: Ollama. Objective: build sysmon.cpp (GetSystemTimes/GlobalMemoryStatusEx/
GetDiskFreeSpaceExW/EnumDisplayDevicesW, Win32 GUI + 1s timer) -> sysmon.exe. max-turns 5.

## Results
| Model | Channel (up front) | Result | Tool calls | Corrections | Time |
|-------|--------------------|--------|-----------|-------------|------|
| gpt-oss:20b | native (native_tools=1) | **PASS** (functional=1) | 5 (3 ok,1 fail) | 0 | 259.8 s |
| qwen3:8b | native (native_tools=1) | INCOMPLETE | 5 (2 ok,3 fail) | 0 | 337.4 s |
| nemotron-3-nano:4b | native (native_tools=1) | INCOMPLETE | 2 (1 ok,1 fail) | 11 | 72.5 s |
| deepseek-coder-v2:16b | text (native_tools=0) | INCOMPLETE | 5 (2 ok,3 fail) | 1 | 86.0 s |

PASS rate: 1/4 (25%) within a 5-productive-turn budget.

## Interpretation
- **Channel profile verified live**: deepseek starts text (native_tools=0), all others native
  (native_tools=1). No HTTP-400 / retry waste for deepseek.
- **gpt-oss:20b** completes the full write->build->fix->finish lifecycle (functional=1).
- **qwen3 / nemotron / deepseek** do not converge to a clean build within budget. nemotron
  shows the edit-feedback loop (11 corrections) — the model struggles to produce a matching
  `old` string; deepseek (text) and qwen3 (native) both stall in build-fix.
- This matches the documented reliability ceiling (~17-42%): the residual gap is
  MODEL-COMPLIANCE bound, not a controller defect. The controller correctly selects the
  channel, parses tool calls, dispatches real tools, feeds back real diagnostics, and
  enforces the independent functional gate.

## State
Fresh evidence recorded. COMMITTED=1 PUSHED=0.
NOT_APPLICABLE: closing the reliability gap to 12/12 — requires model-compliance work
(prompt/few-shot/model choice), not controller code.