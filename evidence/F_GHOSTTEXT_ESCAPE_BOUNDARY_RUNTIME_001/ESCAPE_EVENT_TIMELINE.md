# Escape event timeline

Observed in the candidate Debug pane:

```text
[03:27:02] GHOSTTEXT_TRIGGER request_id=1 generation=14 editor_bytes=39
[03:27:02] GHOSTTEXT_REQUEST_SENT request_id=1
[03:27:10] GHOSTTEXT_ESCAPE_ENTRY request_id=1 generation=14 pending=1 timer=0 active=0 cancellable=1
[03:27:10] GHOSTTEXT_CANCELLED request_id=1 generation_before=14 pending_before=1
[03:27:10] GHOSTTEXT_INVALIDATED request_id=1 generation_after=15 pending_after=0
```

The trigger and cancel occurred on the same isolated candidate. Escape reached the editor boundary while the request was pending.
