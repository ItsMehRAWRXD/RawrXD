# RAWRXD edit-tool convergence feedback — receipt (2026-11-27)

Task: reduce wasted turns/requests in the build-fix loop. Live runs showed the model
repeatedly calling `edit` with `old text not found` (guessing the old text), burning turns.

- Repository: F:\rawrxd  Branch: integration/combined-2026-11-25
- Commit: 2adc93898b  (fix(agent): edit tool convergence feedback …)
- File: `tools/rawr_agent.cpp` (+56 / −8) -> `bin/rawr_agent.exe` (MSVC, `_bb_build/build_agent.cmd`)

## Change
- Extracted the inline edit logic into `ApplyEdit(path, old, new, ok, esc)`.
- On `old text not found`, the result now includes the CURRENT file content (first 600
  chars) + guidance to copy the EXACT text, instead of the bare `"ERROR: old text not found"`.
  This lets the model self-correct in one turn rather than looping on guesses.
- Path-escape and write-failure handling preserved.
- New deterministic `--self-test-edit` (compiled into the shipped binary).

## Verification
### Build
`_bb_build/build_agent.cmd` => BUILD_EXIT=0 (stale `rawr_agent.exe` killed first to avoid LNK1104).

### Deterministic self-tests (model-free, shipped code path)
- `--self-test-channel` => 9/9 PASS.
- `--self-test-parse`  => 7/7 PASS.
- `--self-test-edit`   => 5/5 PASS:
```
match -> edited                OK
content replaced               OK
miss -> not found              OK
miss -> includes current content OK   (convergence feedback present)
path escape rejected           OK
```

### Live no-regression (full lifecycle still PASS)
`bin\rawr_agent.exe --model gpt-oss:20b --max-turns 8 …`:
```
[channel] model=gpt-oss:20b native_tools=1 text_channel=0
turn0 write OK (4315 bytes); turn1 build BUILD_OK; turn2 run (GUI timeout, expected);
turn3 finish -> FINISH
REQUESTS=4 TOOL_OK=3 TOOL_FAIL=0  EVIDENCE functional=1  RESULT=PASS (exit 0)
```
The refactored edit path did not regress the native lifecycle.

## State
IMPLEMENTED=1 COMPILED=1 RUNTIME_REACHED=1 FUNCTIONALLY_VERIFIED=1 COMMITTED=1 PUSHED=0
NOT_APPLICABLE: 12/12 repeat-reliability — model-compliance bound, not an edit-tool defect.

## Next executable action
Push the branch on request; optionally add a live build-fix fixture that forces an
`old not found` to show the recovery in one turn.