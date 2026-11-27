# Production agent-controller deterministic tests — receipt (2026-11-27)

Task: the PRODUCTION shared controller (`src/agent/agent_controller.cpp`, used by both the CLI
and the native IDE) had no deterministic coverage. Add model-free tests for its loop, tool
dispatch, capability gating, no-progress termination, and completion verification.

- Repository: F:\rawrxd  Branch: integration/combined-2026-11-25
- Commit: 4daf93accb
- Files: `tools/agent_controller_selftest.cpp` (new), `_bb_build/build_agent_controller_selftest.cmd` (new)
- Built: `bin\agent_controller_selftest.exe`

## Design
- Scripted `completeFn` replaces the model (no network, no Ollama).
- Real temp-workspace tools: `write_file` (actually writes), `run_build` (deterministic OK).
- `ToolRegistry` method bodies stubbed in the test to avoid linking the 70 KB `rawr_core.cpp`
  + `rawr_edit_rollback.hpp` chain; `Workspace`/`ModeProfile`/`ToolContext`/`InferenceResult`
  are header-inline. Capability gating is exercised (CAP_WRITE / CAP_EXEC vs mode caps).

## Scenarios & result
```
[OK] happy: completed            (write_file + run_build + truthful final => completed)
[OK] happy: file written         (out.txt exists with the written content)
[OK] happy: write+build receipts (>=2 tool results)
[OK] noprogress: not completed   (chatter with no tool/final => bounded no-progress stop)
[OK] noprogress: no tool results
[OK] reject: not completed       (bare final with no real work => completion REJECTED)
[OK] reject: no write happened
[OK] stale: not completed        (source changed AFTER build => F04-V17 staleness REJECTED)
AGENT_CONTROLLER_SELFTEST=PASS (0 fail)
```

## Build
`_bb_build/build_agent_controller_selftest.cmd` => BUILD_EXIT=0
(`cl /std:c++17 /EHsc /I include /I src tools\agent_controller_selftest.cpp src\agent\agent_controller.cpp /link winhttp.lib`).

## State
IMPLEMENTED=1 COMPILED=1 RUNTIME_REACHED=1 FUNCTIONALLY_VERIFIED=1 COMMITTED=1 PUSHED=0
The production controller now has deterministic, model-independent verification of its core
contract (dispatch + capability gate + no-progress + evidence-based completion).

## Next executable action
Push on request. Optionally extend with edit_files/git_diff/run_shell scenarios and a
source-fingerprint staleness case.