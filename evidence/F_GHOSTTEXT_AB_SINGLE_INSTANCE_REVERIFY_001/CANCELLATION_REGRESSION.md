# Cancellation regression

Request A cancellation and generation invalidation were physically observed:

```ini
CANCELLED=PASS_OBSERVED
INVALIDATED=PASS_OBSERVED
PENDING_1_TO_0=PASS_OBSERVED
LATE_A_RENDER=REJECTED
```

This confirms the tested pending-request cancellation path on the candidate. It does not replace the separate explicit Qwen routing or successful-B A/B race gates.
