# T05 Current Candidate Final Receipt

```ini
CANDIDATE_SHA256=2FB9E1B7351EF67AA4876318B6773DBD11AF31D0552ACFC90E61FD080F18A029
SOURCE_COMMIT=bbb26a9e2b230174d06747fa7b6abfc5fad412fb
```

Fresh process, same executable throughout:

1. Request A `T05_BATCH_A_20261104` entered active inference.
2. Stop became enabled and was activated.
3. Chat displayed `[stopped] generation cancelled`.
4. Request B `T05_BATCH_B_20261104` was submitted without restarting.
5. Chat rendered `AI: T05_BATCH_B_20261104`.
6. No Request A response rendered after cancellation.

```ini
REQUEST_A_ACTIVE=PASS
STOP_ENABLED=PASS
STOP_ACKNOWLEDGED=PASS
REQUEST_B_ACCEPTED=PASS
REQUEST_B_EXACT_MARKER=PASS
STALE_A_RENDERED=NOT_OBSERVED
T05=PASS_BEHAVIORAL
```

The process remained responsive and the candidate hash was verified before
execution. A low-level worker-exit receipt was not available, so this is a
behavioral T05 PASS rather than an internal-thread certification.
