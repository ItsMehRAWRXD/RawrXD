# Runtime trace

Observed in the native Debug output of the SHA-verified current binary:

```text
GHOSTTEXT_TRIGGER request_id=1 generation=10 editor_bytes=30
GHOSTTEXT_REQUEST_SENT request_id=1
GhostText inference route: qwen3:8b backend=ollama
GHOSTTEXT_CANCELLED request_id=1 generation_before=10 pending_before=1
GHOSTTEXT_INVALIDATED request_id=1 generation_after=11 pending_after=0
GHOSTTEXT_TRIGGER request_id=2 generation=11 editor_bytes=30
GHOSTTEXT_REQUEST_SENT request_id=2
GhostText inference route: qwen3:8b backend=ollama
GHOSTTEXT_CANCELLED request_id=2 generation_before=11 pending_before=1
GHOSTTEXT_INVALIDATED request_id=2 generation_after=12 pending_after=0
GHOSTTEXT_RESPONSE_RECEIVED request_id=2 success=0 response_bytes=0
GHOSTTEXT_RENDER_DECISION request_id=2 eligible=0
GHOSTTEXT_TRIGGER request_id=3 generation=12 editor_bytes=31
GHOSTTEXT_REQUEST_SENT request_id=3
GhostText inference route: qwen3:8b backend=ollama
GHOSTTEXT_RESPONSE_RECEIVED request_id=3 success=0 response_bytes=0
GHOSTTEXT_RENDER_DECISION request_id=3 eligible=0
GHOSTTEXT_RESPONSE_RECEIVED request_id=1 success=1 response_bytes=107
GHOSTTEXT_RENDER_DECISION request_id=1 eligible=0
```

The trace proves explicit routing, cancellation, stale-response fencing, and late-A rejection. It also proves that the newer request did not render because the shared inference scheduler rejected it while request A was still active.
