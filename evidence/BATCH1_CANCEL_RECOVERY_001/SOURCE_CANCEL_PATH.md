# SOURCE_CANCEL_PATH — BATCH1_CANCEL_RECOVERY_001

ASOF_UTC=2026-11-03T05:25:00Z
PROMOTE=0
CERTIFIED=0
SEAL_AUTHORITY_TOUCHED=0

## Read: stopInference / generateOllamaModel / generateResponseAsync

Tip source: `F:\rawrxd\src\win32app\Win32IDE.cpp` (+ `Win32IDE.h`).

### Cancelable HTTP — YES (parent fix landed in tip source)

- `OllamaHttpCancelSlots` publishes live `HINTERNET` session/connect/request into
  `m_ollamaHttpSession` / `m_ollamaHttpConnect` / `m_ollamaHttpRequest`.
- `generateOllamaModel(..., cancelSlots)` checks `stopRequested` around
  Send/Receive/Read and returns `"[Ollama request cancelled]"`.
- `Win32IDE::abortActiveOllamaHttp()` closes request→connect→session via
  `WinHttpCloseHandle` to unblock a stuck `ReceiveResponse`.
- `Win32IDE::stopInference()`:
  1. `m_inferenceStopRequested = true`
  2. `m_activeInferenceGeneration = 0`
  3. `abortActiveOllamaHttp()`
  4. **`m_inferenceRunning = false` immediately** (Request B admission)
- `finishIfCurrent` does **not** clear `m_inferenceRunning` when stop already
  released ownership / a newer generation owns the slot (avoids clobbering B).

### Prior defect (pre-fix)

Stop UI cleared (`HandleCopilotStop`) while sync Ollama WinHTTP left
`m_inferenceRunning=true` until receive completed → Request B status
`"Inference is already running; press Stop before sending another message."`

## Tip binary vs seal

| Path | Role |
|------|------|
| `F:\rawrxd\build_modelroute\bin\Release\RawrXD-Win32IDE-Native.exe` | Tip test target |
| `F:\rawrxd\.worktrees\product_seal_clean_a5ae60ef_build\bin\RawrXD-Win32IDE-Native.exe` | Seal authority `CB34EF4E…` — **not replaced** |
