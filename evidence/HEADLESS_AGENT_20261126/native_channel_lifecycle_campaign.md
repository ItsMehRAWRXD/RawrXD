# RAWRXD native/text tool-channel lifecycle campaign — evidence (2026-11-27)

Controller: `tools/rawr_agent.cpp` @ commit 63cb5b4f88 (per-provider channel profile),
rebuilt `bin/rawr_agent.exe` at HEAD. Backend: Ollama (127.0.0.1:11434).
Objective (all runs): create `sysmon.cpp` (GetSystemTimes / GlobalMemoryStatusEx /
GetDiskFreeSpaceExW / EnumDisplayDevicesW, Win32 GUI + 1s timer) + `build.cmd` -> `sysmon.exe`.

## Result summary
| Model | Channel (up front) | Lifecycle | RESULT | Requests | Time |
|-------|--------------------|-----------|--------|----------|------|
| gpt-oss:20b | native (`native_tools=1`) | write->build(FAIL)->edit->build(OK)->finish | **PASS** (functional=1) | 5 | 57.4 s |
| qwen3:8b | native (`native_tools=1`) | write->build(FAIL)->edit->build(FAIL)->edit->edit | INCOMPLETE (turn budget) | 6 | 102.2 s |
| deepseek-coder-v2:16b | text (`native_tools=0`) | write (first request) | text-branch OK (bounded) | 1 | 78.6 s |
| qwen2.5-coder:1.5b-base | native -> non-silent fallback | fallback to text | fallback path OK (bounded) | 2 | 21.7 s |

## gpt-oss:20b — full native lifecycle PASS (primary evidence)
```
[channel] model=gpt-oss:20b native_tools=1 text_channel=0
[turn 0] model_tool=write (phase=1)      -> OK wrote sysmon.cpp (4320 bytes)
[turn 1] model_tool=build (phase=2)      -> COMPILE_FAILURE: C2664 LoadCursorW(HINSTANCE,LPCWSTR) from LPSTR
[turn 2] model_tool=edit  (phase=2)      -> OK edited sysmon.cpp
[turn 3] model_tool=build (phase=2)      -> BUILD_OK: sysmon.exe produced
[turn 4] model_tool=finish(phase=5)      -> FINISH: sysmon.exe built successfully and ready for use.
REQUESTS=5 TOOL_CALLS=5 TOOL_OK=3 TOOL_FAIL=1 CORRECTIONS=0
EVIDENCE functional=1  RESULT=PASS  (exit 0)
```
The controller selected native up front, parsed native `message.tool_calls`, executed real
write/build/edit, fed back real compiler diagnostics, and its INDEPENDENT functional gate
(`VerifyFunctional`: source created this session + real Win32 APIs + exe launches) verified the
deliverable before accepting `finish`.

## qwen3:8b — native channel flows correctly; INCOMPLETE is model convergence, not the channel
```
[channel] model=qwen3:8b native_tools=1 text_channel=0
turn0 write OK (2268 bytes); turn1 build COMPILE_FAILURE(C2664 GetSystemTimes);
turn2 edit OK; turn3 build COMPILE_FAILURE(C2065 'systime'); turn4 edit; turn5 edit
RESULT=INCOMPLETE (max-turns=6 reached before a clean build)
```
Native tool calls (write/build/edit) were parsed and executed every turn; the model did not
converge to a successful build within the budget (documented model-compliance gap).

## deepseek-coder-v2:16b — text channel from turn 0 (documented problem closed)
```
[channel] model=deepseek-coder-v2:16b native_tools=0 text_channel=1
[turn 0] model_tool=write -> OK wrote sysmon.cpp (3506 bytes); REQUESTS=1
```
No HTTP-400, no 3x retry / 2x2 s sleep waste; a real tool call landed on the first request.

## qwen2.5-coder:1.5b-base — non-silent, provider-attributed fallback
```
[channel] model=qwen2.5-coder:1.5b-base native_tools=1 text_channel=0
[turn 0] native tool channel rejected by provider 'qwen2.5-coder:1.5b-base' (3 attempts); switching to text channel …
```
Up-front native selection + explicit fallback (previously a silent permanent downgrade).

## Deterministic (model-free) profile check
`bin\rawr_agent.exe --self-test-channel` => 9/9 OK, `SELFTEST_CHANNEL=PASS` (deepseek->text;
gpt-oss/qwen3/nemotron/llama/unknown->native).

## State
IMPLEMENTED=1 COMPILED=1 RUNTIME_REACHED=1 FUNCTIONALLY_VERIFIED=1 (gpt-oss full lifecycle PASS)
COMMITTED=1 (impl 63cb5b4f88, receipt da1964493d) PUSHED=0
NOT_APPLICABLE: 12/12 repeat-reliability target — residual gap is model-compliance bound
(reliability_final.txt / reliability_rootcause.txt), not a controller/channel defect.

## Next executable action
Push `integration/combined-2026-11-25` if remote landing is desired; optionally widen the
campaign (nemotron, more seeds) for a reliability distribution.