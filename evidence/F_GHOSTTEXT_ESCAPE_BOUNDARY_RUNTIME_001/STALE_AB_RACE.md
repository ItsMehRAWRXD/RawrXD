# Stale A/B race

Status: `NOT_VERIFIED`.

The run verified a cancelled request and a late-response render rejection, but did not produce two deliberately overlapping requests with reordered A/B responses. A separate controlled delayed-response harness is still required for that scenario.
