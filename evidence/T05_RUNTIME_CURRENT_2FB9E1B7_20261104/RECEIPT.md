# T05 Current-Hash Replay

```ini
CANDIDATE_SHA256=2FB9E1B7351EF67AA4876318B6773DBD11AF31D0552ACFC90E61FD080F18A029
SOURCE_COMMIT=bbb26a9e2b230174d06747fa7b6abfc5fad412fb
```

## Observed sequence

- Fresh native IDE launched from the candidate path.
- Request A submitted and Stop was enabled during active inference.
- Stop was activated; the chat displayed `[stopped] generation cancelled`.
- Request B was entered and Send was activated.
- No fresh visible `T05_CURRENT_B_20261104` response was observed during the controlled observation window.

## Disposition

```ini
REQUEST_A_ACTIVE=PASS
STOP_ENABLED=PASS
STOP_ACKNOWLEDGED=PASS
REQUEST_A_LATE_RENDER=NOT_OBSERVED
REQUEST_B_VISIBLE_COMPLETION=NOT_VERIFIED
T05_CURRENT_HASH=NOT_VERIFIED
```

This receipt supersedes no prior evidence. The earlier behavioral PASS belongs to a different SHA and is not inherited.
