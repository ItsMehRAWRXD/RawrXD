# CHATWINDOW_FIRST_MISSING_TRANSITION

ASOF_UTC=2026-11-02T13:28:00Z
CANDIDATE_SHA256=CB34EF4E1A3C964ADEC18F02ABBE605B85CB83F10961BCA6A9DB2D812FC0C6FB
PROMOTE=0
INVENT_PASS=0

## First missing transition

**Name:** `BACKEND_GENERATE_HTTP_COMPLETE`
**After:** `MODEL_LOAD=PASS` (OBSERVED)
**Before:** worker `finish()` → UI callback → chat output render

**Class:** `FAIL` against ChatWindow E2E acceptance (120s); underlying OS/HTTP outcome still `NOT_VERIFIED` (may have been in-flight under 600s receive timeout when harness tore down).

## Why this is first

Proven earlier steps:

1. UI Send → `HandleCopilotSend` (effect: ollama_debug created).
2. Route = Ollama HTTP `generateOllamaModel`.
3. Model selected = `bigdaddyg-productivity-local:latest`.
4. Completion capability probe passed (`MODEL_LOAD=PASS`).

Not proven:

5. `WinHttpSendRequest` / `WinHttpReceiveResponse` returned.
6. Raw JSON received / parsed.
7. `GENERATED_TOKENS` logged.
8. `onResponse` / `handleCopilotUiUpdate` ran.
9. Output HWND text grew / status became `Ollama: response received`.

Therefore the break is not "UI refused a completed response" and not "routing never left the UI." The first gap is **post-admission-admission generate completion**.

## What a missing UI response does not prove

| Claim | Supported? |
|-------|------------|
| Backend never received work | No — MODEL_LOAD and generateOllamaModel entry logs exist |
| Backend definitely failed | No — no WinHTTP error line; process not crashed |
| Callback/render bug alone | No — no completion payload reached the callback instrumentation |
| Cancel invalidated response | No — Stop was disabled; cancel not effective |

## Secondary missing (cancel path)

**Name:** `STOP_ENABLED_AFTER_SEND`
**Class:** `FAIL` (observed `cancelEnabled=0`)
`HandleCopilotSend` sets `session->running = true` but does not enable Stop before `generateResponseAsync`. Stop is created disabled. Cancel could not be demonstrated.
