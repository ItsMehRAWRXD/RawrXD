# Verification receipt

Validated in the ChatGPT Linux build environment on 2026-09-28.

## Compile

```text
g++ -std=c++20 -O2 -Wall -Wextra -Wpedantic rawrxd_scale_value_pack.cpp -o RawrXD-Scale-test
RESULT=PASS
```

## Persistent index/search

```text
GATE=RAWRXD_LOCAL_INDEX_001
DISCOVERED=2
REUSED=0
REINDEXED=2
REMOVED=0
VERDICT=PASS
```

Search returned both seeded source files ranked for `Deep2 chat stream callback`.

## Durable checkpoint/restore

A checkpoint was created, a source file was overwritten, and restore recovered the original bytes.

```text
GATE=RAWRXD_CHECKPOINT_CREATE_001
VERDICT=PASS
GATE=RAWRXD_CHECKPOINT_RESTORE_001
VERDICT=PASS
CHECKPOINT_SMOKE=PASS
```

## Isolated agent-session manager

The orchestration layer was exercised with a local disposable child-process test harness (not shipped in this pack) that mutated only its isolated session workspace. The manager detected the change and merged it to the base workspace through the baseline-hash gate.

```text
GATE=RAWRXD_ISOLATED_AGENT_SESSION_001
EXIT_CODE=0
TIMED_OUT=0
CHANGED_FILES=1
SESSION_SUCCESS=1
MERGED_FILES=1
MERGE_CONFLICTS=0
MERGE_VERDICT=PASS
VERDICT=PASS
```

This validates the orchestration mechanics, not Deep2 inference. Real Deep2 E2E requires running the shipped manager against the user's actual `RawrXD-Agentic.exe` and GGUF model.

## Parallel conflict protection

Two isolated child sessions changed the same source file from the same baseline. The first merged. The second was refused as a conflict rather than overwriting live work.

```text
GATE=RAWRXD_MULTI_AGENT_ORCHESTRATION_001
TASKS=2
SUCCEEDED=2
FAILED=0
MERGED_FILES=1
MERGE_CONFLICTS=1
VERDICT=HOLD
MULTI_AGENT_CONFLICT_SMOKE=PASS
```

`HOLD` is the expected result for an intentional conflict test.

## Remaining platform-specific verification

The `_WIN32` branch uses `CreateProcessW`, redirected pipes and a Job Object for timeout containment. It has not been compiled with the user's MSVC/Windows SDK in this environment. Run the included PowerShell certification script on the RawrXD Windows workstation before marking the Windows gate PASS.
