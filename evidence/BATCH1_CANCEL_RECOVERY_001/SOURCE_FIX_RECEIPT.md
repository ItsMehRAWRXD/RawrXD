# BATCH1_CANCEL_RECOVERY_001 — Source fix receipt

ASOF_LOCAL=2026-11-03
PROMOTE=0
CERTIFIED=0
REBUILD_AUTHORITY=0
SEAL_CB34EF4E_UNCHANGED=1

## Defect (audit gates 04–08 / Batch1 10–11)

```
Stop clicked
→ UI stopped
→ synchronous Ollama WinHTTP still blocked in ReceiveResponse
→ m_inferenceRunning stayed true until worker completed
→ Request B rejected ("Inference is already running")
```

## Source fix (tip WIP / build_modelroute — NOT seal authority)

1. `generateOllamaModel` accepts `OllamaHttpCancelSlots` and publishes session/connect/request handles.
2. `Win32IDE::abortActiveOllamaHttp()` closes live handles (request first).
3. `stopInference()` sets stop + generation=0, aborts HTTP, **immediately** clears `m_inferenceRunning`.
4. `finishIfCurrent` no longer clears busy state for a newer Request B generation.
5. Owned-handle close uses CAS so Stop and worker never double-`CloseHandle`.

## Binary policy

- Seal candidate `CB34EF4E…` / `a5ae60ef` **not** rebuilt or replaced.
- Tip `build_modelroute` rebuild is investigation / recovery candidate only.

## Runtime

`RUNTIME_CANCEL_RECOVERY=NOT_RUN` until harness exercises Stop → Request B on a named SHA.
