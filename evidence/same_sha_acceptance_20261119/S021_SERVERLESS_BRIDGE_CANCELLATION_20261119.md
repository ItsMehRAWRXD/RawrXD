# S021 — Serverless Deep2 bridge cancellation

Date: 2026-11-19  
Source SHA: `432506f31488d9c0707bf7f8cdc3057df826bb76`

## Source behavior

The Deep2 bridge has an atomic cancellation path:

```text
Deep2Bridge::Cancel()
  m_cancelRequested = true

GenerateStream token callback
  callback returns false
    m_cancelRequested = true
    Deep2Engine::requestCancel()
  callback return value = !m_cancelRequested

worker completion
  OnGenerationComplete(m_cancelRequested)
```

`Stop()` also sets both stop and cancel flags and joins the generation worker.
The completion callback is emitted from `OnGenerationComplete`, including the
cancelled state through the ESP event path.

## Acceptance status

No runtime cancellation receipt exists in the retained S018/S019 artifacts,
and the standalone harness remains unbuilt because it has no CMake target.
Therefore interruption latency, stale-callback suppression, and cleanup after
cancellation remain OPEN.

```ini
CANCELLATION_SOURCE=FOUND
ENGINE_REQUEST_CANCEL=Wired
WORKER_JOIN=Implemented
CANCELLATION_RUNTIME=NOT_RUN
STALE_CALLBACK_TEST=NOT_RUN
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```
