# Pipeline self-test flakiness — root cause & fix (2026-11-27)

## Symptom
`--self-test-pipeline` (and the full acceptance batch) failed intermittently at the
"functional gate PASS" check — passed standalone sometimes, failed in batch, then failed
consistently. Build + short-circuit checks always passed.

## Root cause (diagnosed, not guessed)
The pipeline test's inline GUI source declared `DISPLAY_DEVICEW d;` **uninitialized** and
passed `&d` to `EnumDisplayDevicesW`. That API reads `d.cb` (must equal `sizeof(DISPLAY_DEVICEW)`);
with a garbage stack value the call corrupted/failed nondeterministically and the process
exited with **0xC0000409 = STATUS_STACK_BUFFER_OVERRUN** (confirmed via
`Start-Process -Wait -PassThru` -> ExitCode -1073740791). Because the stack garbage varied
run to run, the functional gate was flaky. This was a TEST-SOURCE defect, not a controller defect.

A secondary, real robustness gap was also fixed: `VerifyFunctional` could fail if
`CreateProcessW` hit a transient lock on a freshly-linked exe; it now retries briefly.

## Fix (commit f113d98292, tools/rawr_agent.cpp)
- Test source: `DISPLAY_DEVICEW d{}; d.cb = sizeof(d);` before `EnumDisplayDevicesW`.
- `VerifyFunctional`: bounded `CreateProcessW` retry (6 x 150 ms) for a momentarily locked exe.

## Verification
- Build: `_bb_build/build_agent.cmd` => BUILD_EXIT=0.
- `--self-test-pipeline`: 4/4 consecutive PASS (was flaky).
- Full acceptance (all together):
```
SELFTEST_CHANNEL=PASS   SELFTEST_PARSE=PASS   SELFTEST_EDIT=PASS
SELFTEST_GUIRUN=PASS    SELFTEST_PIPELINE=PASS
AGENT_CONTROLLER_SELFTEST=PASS
```

## State
IMPLEMENTED=1 COMPILED=1 RUNTIME_REACHED=1 FUNCTIONALLY_VERIFIED=1 COMMITTED=1 PUSHED=0
The deterministic suite is now stable (no flakiness) and green end-to-end.