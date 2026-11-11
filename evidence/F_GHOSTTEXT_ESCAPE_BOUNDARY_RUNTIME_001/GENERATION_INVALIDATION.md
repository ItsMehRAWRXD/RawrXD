# Generation invalidation

`generation_before=14` and `generation_after=15` were observed for request 1. `pending_before=1` changed to `pending_after=0`. This is direct runtime evidence that Escape invalidated the pending generation.

The eventual response was observed after cancellation:

```text
GHOSTTEXT_RESPONSE_RECEIVED request_id=1 success=1 response_bytes=39 generated_tokens=N/A generation_current=0 identity_current=1 snapshot_current=1
GHOSTTEXT_RENDER_DECISION request_id=1 eligible=0
```

The response was rejected by the render gate (`eligible=0`).
