# RAWRXD_PROVIDER_TOOL_CHANNEL_PROFILE — implementation receipt (2026-11-27)

Task: implement the `provider_compliance.txt` (2026-11-27) recommendation in the headless
agent controller so the tool channel is a **provider property selected up front**, not a
per-request reactive discovery.

- Repository: F:\rawrxd
- Branch: integration/combined-2026-11-25
- Commit: 63cb5b4f88  (feat(agent): per-provider tool-channel profile …)
- File changed: `tools/rawr_agent.cpp` (+52 / −3), built to `bin/rawr_agent.exe`
- Controller under test: `tools/rawr_agent.cpp` (built by `_bb_build/build_agent.cmd`, MSVC cl)

## Change
- `ProviderSupportsNativeTools(model)`:
  - `deepseek*`  -> **text** channel (server rejects the tools schema, HTTP 400).
  - `gpt-oss` / `qwen3` / `nemotron` / others -> **native** `message.tool_calls`.
  - case-insensitive; unknown model -> native (safe default).
- Channel is chosen **up front** (`useTools = ProviderSupportsNativeTools(model)`), replacing
  the old `useTools = true` + reactive flip.
- Startup line: `[channel] model=<m> native_tools=<0|1> text_channel=<0|1>`.
- Reactive fallback is now **non-silent and provider-attributed**:
  `[turn N] native tool channel rejected by provider '<m>' (3 attempts); switching to text channel …`.
- Hidden deterministic self-test: `--self-test-channel` (compiled into the shipped binary).

## Why (documented gap this closes)
Old behavior discovered native-tool rejection only after a failed request and then permanently
set `useTools=false` on the FIRST transport failure. Consequences:
1. deepseek wasted 3 HTTP round-trips + 2×2 s sleeps every session before downgrading.
2. a capable model (gpt-oss/qwen3/nemotron) hitting a transient failure was silently and
   permanently downgraded to text for the rest of the session.
Selecting the channel from the provider up front removes both.

## Verification evidence
### 1. Build (MSVC)
`_bb_build/build_agent.cmd` -> `bin/rawr_agent.exe`  => BUILD_EXIT=0 (clean rebuild at HEAD).

### 2. Deterministic self-test (model-free, shipped code path)
`bin\rawr_agent.exe --self-test-channel` => SELFTEST_EXIT=0, 9/9 OK:
```
deepseek-coder-v2:16b  native=0 OK      gpt-oss:20b   native=1 OK
deepseek-r1:32b        native=0 OK      gpt-oss:120b  native=1 OK
DeepSeek-V2-Lite       native=0 OK      qwen3:8b      native=1 OK
nemotron-3-nano:4b     native=1 OK      llama3.2:3b   native=1 OK
unknown-model:latest   native=1 OK
SELFTEST_CHANNEL=PASS (0 fail)
```

### 3. Live deepseek (text channel from turn 0 — the documented problem)
`bin\rawr_agent.exe --model deepseek-coder-v2:16b --max-turns 1 …`:
```
[channel] model=deepseek-coder-v2:16b native_tools=0 text_channel=1
[turn 0] model_tool=write (phase=1)
  -> OK wrote …\sysmon.cpp (3506 bytes)
REQUESTS=1  TOOL_CALLS=1  TOOL_OK=1  TOOL_FAIL=0
```
=> deepseek starts in text, lands a real tool call on the FIRST request, no HTTP-400, no retry/sleep waste.

### 4. Live native-profile model (non-silent fallback path)
`bin\rawr_agent.exe --model qwen2.5-coder:1.5b-base --max-turns 1 …`:
```
[channel] model=qwen2.5-coder:1.5b-base native_tools=1 text_channel=0
[turn 0] native tool channel rejected by provider 'qwen2.5-coder:1.5b-base' (3 attempts); switching to text channel …
```
=> up-front native selection + explicit, provider-attributed fallback (previously a silent downgrade).

### 5. Corroboration (peer commit)
`a665e29c15 test(agent): transport fully implemented — gpt-oss native end-to-end PASS
(write->build->finish, functional)` — independent evidence the native path completes a full
lifecycle on gpt-oss.

## State
IMPLEMENTED=1 COMPILED=1 RUNTIME_REACHED=1 FUNCTIONALLY_VERIFIED=1 COMMITTED=1 PUSHED=0
NOT_APPLICABLE: full 12/12 repeat-reliability campaign — the residual gap is model-compliance
bound (see reliability_final.txt / reliability_rootcause.txt), not a controller defect; out of
scope for this bounded change.

## Next executable action
Push `integration/combined-2026-11-25` if remote landing is desired; then run a broader live
campaign (gpt-oss:20b / qwen3:8b / nemotron) to reconfirm native-channel reliability under the
new up-front selection.