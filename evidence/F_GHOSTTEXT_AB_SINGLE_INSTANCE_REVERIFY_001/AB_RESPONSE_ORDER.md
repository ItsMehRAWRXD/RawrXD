# A/B response order

Observed:

```text
[03:38:59] GHOSTTEXT_RESPONSE_RECEIVED request_id=2 success=0 response_bytes=0
[03:38:59] GHOSTTEXT_RENDER_DECISION request_id=2 eligible=0
[03:39:19] GHOSTTEXT_RESPONSE_RECEIVED request_id=1 success=1 response_bytes=73
[03:39:19] GHOSTTEXT_RENDER_DECISION request_id=1 eligible=0
```

The configured delay caused A's response to arrive after B, and A was rejected. However, B did not produce a successful response, so the required “newer B renders while stale A is rejected” acceptance condition was not met.
