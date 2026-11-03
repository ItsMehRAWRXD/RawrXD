# Test seam design

The candidate adds a bounded callback delay immediately before the existing `PostMessageA` result delivery. It is enabled only when both `RAWRXD_GHOSTTEXT_TEST_DELAY_A_MS` and `RAWRXD_GHOSTTEXT_TEST_DELAY_B_MS` are present. Request IDs and generations are untouched; the normal UI render path remains authoritative.

Allowed delay is 1–30000 ms. Missing, malformed, zero, or excessive values disable the seam.
