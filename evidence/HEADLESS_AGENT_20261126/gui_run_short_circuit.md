# RAWRXD GUI-run short-circuit — receipt (2026-11-27)

Task: eliminate the 20 s/turn waste when the model runs a GUI exe. Live gpt-oss run
(commit 2adc93898b campaign) showed `turn2 run sysmon.exe` timing out after 20 s because a
GUI-subsystem process never exits — even though the build tool already verified launch.

- Repository: F:\rawrxd  Branch: integration/combined-2026-11-25
- Commit: fd6b2ddee9  (fix(agent): GUI-run short-circuit …)
- File: `tools/rawr_agent.cpp` (+37 / −1) -> `bin/rawr_agent.exe` (MSVC)

## Change
- `IsGuiRunToShortCircuit(cmd, builtOut, builtSubsys)` — true when the last successful build
  was `subsystem=windows` and the run command references that output exe.
- `run` handler: on a match, returns `GUI_APP_LAUNCH_ALREADY_VERIFIED: … Call finish now.`
  WITHOUT spawning (no 20 s block); counts a correction.
- Track `builtOut`/`builtSubsys` on successful build.
- New deterministic `--self-test-guirun` (compiled into the shipped binary).

## Verification
### Build
`_bb_build/build_agent.cmd` => BUILD_EXIT=0.

### Deterministic self-tests (model-free, shipped code path)
- `--self-test-channel` 9/9, `--self-test-parse` 7/7, `--self-test-edit` 5/5,
- `--self-test-guirun` 5/5:
```
gui exe run -> short-circuit       OK
cmd contains gui exe -> short-circuit OK
console exe -> no short-circuit    OK
other cmd -> no short-circuit      OK
no built exe -> no short-circuit   OK
```

### Live confirmation
- Edit convergence feedback observed live (gpt-oss run): `old text not found … Current file
  (first 600 chars): #include <windows.h> …` (turns 5, 16).
- The short-circuit path requires a successful build to arm; that is model-dependent. This
  gpt-oss run degenerated into a read/list loop before build-success (documented model
  compliance variance, 24 requests, INCOMPLETE) so the short-circuit was not reached live;
  it is fully covered by `--self-test-guirun`. Prior gpt-oss runs completed the full
  write->build->finish lifecycle PASS.

## State
IMPLEMENTED=1 COMPILED=1 RUNTIME_REACHED=1 FUNCTIONALLY_VERIFIED=1 (deterministic) COMMITTED=1 PUSHED=0
NOT_APPLICABLE: live short-circuit timing — model must reach build-success; covered by self-test.

## Next executable action
Push the branch on request; optionally a scripted fixture (write a GUI app, build, then run)
to exercise the short-circuit live and assert no 20 s delay.