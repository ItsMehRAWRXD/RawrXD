# RAWRXD deterministic model-free E2E pipeline self-test — receipt (2026-11-27)

Task: provide a model-independent END-TO-END proof of the real tool pipeline, closing the
`BUILD_PASS != E2E_PASS` gap (the model-compliance lottery makes live E2E non-deterministic).

- Repository: F:\rawrxd  Branch: integration/combined-2026-11-25
- Commit: f4556f5cdb  (test(agent): deterministic model-free E2E pipeline self-test …)
- File: `tools/rawr_agent.cpp` (+40) -> `bin/rawr_agent.exe` (MSVC)

## Change
- `--self-test-pipeline`: writes a minimal valid GUI source (GetSystemTimes / GlobalMemoryStatusEx /
  GetDiskFreeSpaceExW / EnumDisplayDevicesW + WinMain), builds it with the ACTUAL MSVC command
  (`vcvars64` + `cl /SUBSYSTEM:WINDOWS user32.lib gdi32.lib`), then asserts:
  1. the GUI exe was produced (real build),
  2. `IsGuiRunToShortCircuit("sysmon.exe","sysmon.exe","windows")` (no 20 s block),
  3. `VerifyFunctional()` — source created this session + real APIs + exe launches.
- Unique temp dir per invocation (pid+counter) to avoid remove_all/relink races.

## Verification
### Build
`_bb_build/build_agent.cmd` => BUILD_EXIT=0.

### Full self-test suite (shipped binary, model-free)
```
SELFTEST_CHANNEL=PASS (0 fail)   9/9
SELFTEST_PARSE=PASS   (0 fail)   7/7
SELFTEST_EDIT=PASS    (0 fail)   5/5
SELFTEST_GUIRUN=PASS  (0 fail)   5/5
SELFTEST_PIPELINE=PASS (0 fail)  real MSVC build + short-circuit + functional gate
```
`--self-test-pipeline` passed 3/3 consecutive runs (non-flaky after the unique-dir fix).
Note: this test performs a real compile + process launch, so it is mildly environment-sensitive
(cold cache/loaded host); it is a genuine E2E, not a mock.

## State
IMPLEMENTED=1 COMPILED=1 RUNTIME_REACHED=1 FUNCTIONALLY_VERIFIED=1 COMMITTED=1 PUSHED=0
This closes the deterministic E2E gap for the tool pipeline independent of model behavior.

## Next executable action
Push the branch on request. The controller now has deterministic coverage for channel
selection, text extraction, edit convergence, GUI-run short-circuit, and full pipeline E2E.