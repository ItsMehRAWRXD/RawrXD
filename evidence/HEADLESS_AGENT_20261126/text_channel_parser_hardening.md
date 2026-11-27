# RAWRXD text-channel tool-extraction hardening — receipt (2026-11-27)

Task: harden the text-channel tool-call parser in the headless controller. The text channel
is now the PRIMARY path for deepseek (per-provider profile, commit 63cb5b4f88), but the old
`FirstJsonObject()` returned the FIRST balanced `{...}` in the model content — fragile when a
model emits prose or a reasoning/example object before the real tool call.

- Repository: F:\rawrxd  Branch: integration/combined-2026-11-25
- Commit: fdb335a0d9  (fix(agent): harden text-channel tool extraction …)
- File: `tools/rawr_agent.cpp` (+58 / −12) -> `bin/rawr_agent.exe` (MSVC, `_bb_build/build_agent.cmd`)

## Change
- Removed `FirstJsonObject()`; added:
  - `IsKnownTool(name)` — tool ∈ {write, build, edit, read, list, run, finish}.
  - `ExtractToolObject(text)` — scans EVERY balanced `{...}` and returns the first whose
    `"tool"` is a known tool; reasoning/example objects (no known tool) are skipped.
- Text-channel fallback now: `call = ExtractToolObject(content)`.
- New deterministic `--self-test-parse` (compiled into the shipped binary).

## Verification
### Build
`_bb_build/build_agent.cmd` => BUILD_EXIT=0.
(Note: a first link attempt hit LNK1104 because a lingering `rawr_agent.exe` from a prior
background run held the file; killed the stale process, rebuilt clean.)

### Deterministic self-tests (model-free, shipped code path)
- `--self-test-channel` => 9/9 OK, `SELFTEST_CHANNEL=PASS`.
- `--self-test-parse` => 7/7 OK, `SELFTEST_PARSE=PASS`:
```
expect=write  got=write  OK     (pure JSON)
expect=build  got=build  OK     (prose before JSON)
expect=edit   got=edit   OK     (reasoning/note object BEFORE real call -> skipped)
expect=list   got=list   OK     (lead-in prose)
expect=       got=       OK     (reasoning-only object -> no tool)
expect=       got=       OK     (no JSON)
expect=finish got=finish OK     (non-tool object, then real call)
```

### Live text-channel (no regression)
`bin\rawr_agent.exe --model deepseek-coder-v2:16b --max-turns 1 …`:
```
[channel] model=deepseek-coder-v2:16b native_tools=0 text_channel=1
[turn 0] model_tool=write -> OK wrote …\sysmon.cpp (2738 bytes); REQUESTS=1
```
Text channel still extracts and executes the real tool call on the first request.

## State
IMPLEMENTED=1 COMPILED=1 RUNTIME_REACHED=1 FUNCTIONALLY_VERIFIED=1 COMMITTED=1 PUSHED=0
NOT_APPLICABLE: 12/12 repeat-reliability — model-compliance bound, not a parser defect.

## Next executable action
Push the branch on request; optionally add a live prose-wrapped deepseek fixture to the
campaign for a regression example.