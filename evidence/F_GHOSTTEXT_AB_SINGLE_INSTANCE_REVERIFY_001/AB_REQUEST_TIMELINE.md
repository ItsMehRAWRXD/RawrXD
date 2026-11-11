# A/B request timeline

Observed in the candidate Debug pane:

```text
[03:38:47] GHOSTTEXT_TRIGGER request_id=1 generation=10 editor_bytes=5
[03:38:47] GHOSTTEXT_REQUEST_SENT request_id=1
[03:38:58] GHOSTTEXT_CANCELLED request_id=1 generation_before=10 pending_before=1
[03:38:58] GHOSTTEXT_INVALIDATED request_id=1 generation_after=11 pending_after=0
[03:38:58] GHOSTTEXT_TRIGGER request_id=2 generation=11 editor_bytes=6
[03:38:58] GHOSTTEXT_REQUEST_SENT request_id=2
```

Request A was invalidated before request B was issued.
