# CHATWINDOW_ROOT_CAUSE_CANDIDATES

ASOF_UTC=2026-11-02T13:28:00Z
CANDIDATE_SHA256=CB34EF4E1A3C964ADEC18F02ABBE605B85CB83F10961BCA6A9DB2D812FC0C6FB
Read-only. No ranking invented as CERTAIN without further probe.

## Ranked candidates (diagnostic, not fixes)

### RC1 — Long-running / stuck non-streaming Ollama generate (most consistent)

**Hypothesis:** After `MODEL_LOAD=PASS`, worker blocked in `WinHttpReceiveResponse`/`WinHttpReadData` for `POST /api/generate` with `stream:false`, `num_ctx=65536`, `num_predict≈512`, model `bigdaddyg-productivity-local:latest`. Harness waited 120s then killed the process before the 600s product timeout and before any completion log line.

**Supports:** ollama_debug truncates exactly before Raw/WinHTTP failure lines; CRASH=0 during wait; large model + huge ctx; code comments admit multi-minute local generates.
**Against:** Could also be silent hang inside Ollama itself (still "backend completion missing").
**Class if confirmed:** runtime FAIL (product E2E), not missing instrumentation for the completion markers (those markers exist in source and simply never fired).

### RC2 — Model combo fell through to a heavy default (COMBO_INDEX_0)

**Hypothesis:** Preferred small models did not match combo strings; index 0 resolved to `bigdaddyg-productivity-local:latest`, amplifying RC1.

**Supports:** RUNLOG `MODEL_COMBO_COUNT=45 (no preferred name matched)` + ollama model name.
**Class:** OBSERVED routing choice; contributory, not the sole defect.

### RC3 — Stop control never armed → cancel path cannot salvage hung generate

**Hypothesis:** Product leaves Stop disabled after send, so harness cannot cancel; teardown is the only abort.

**Supports:** `cancelEnabled=0`; Stop created disabled; `HandleCopilotSend` does not enable it before async generate.
**Class:** OBSERVED product behavior / FAIL for CANCEL_OK; distinct from response render.

### RC4 — Callback / UI render defect

**Hypothesis:** Backend completed but UI dropped the update.

**Supports:** none in this run (no GENERATED_TOKENS, no status `Ollama: response received`, empty output capture).
**Class:** NOT_VERIFIED — must not be asserted as root cause from this evidence.

### RC5 — Missing request/generation ID instrumentation

**Hypothesis:** Harder to correlate Ollama server logs with UI sessions.

**Supports:** no requestId/generationId in ollama_debug schema.
**Class:** NOT_INSTRUMENTED — does not by itself explain RESPONSE_OK=0.

## Explicit non-causes (this evidence)

- Host prereq failure (Ollama was up; free RAM/disk noted in receipt).
- Candidate SHA drift (pre-hash match).
- Qt ChatWindow absence (Native Copilot surface used intentionally).
- `deep2_qgemv.spv` worktree artifact (ChatWindow path used Ollama HTTP).

## Next probe (still REBUILD=0, same SHA)

1. Re-run ChatWindow with forced small Ollama model match, or extend wait while tailing `ollama_debug.log` / `ollama ps`.
2. Confirm whether `/api/generate` is active during the 120s window.
3. Hold GhostText/64-token until ChatWindow completion is observed or a WinHTTP error line is sealed.
