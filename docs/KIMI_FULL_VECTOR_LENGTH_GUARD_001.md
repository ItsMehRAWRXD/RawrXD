# RawrXD numerical parity — canonical-base complete-vector guard

Canonical base: `bba91a7ae0c0b84096d0e33e5d55a4449997e191`.
Existing draft PRs #62 and #63 were audited before this branch was created. The canonical branch advanced by two commits after PR #63 was based, including Q6_K parity and post-fence changes. This branch deliberately carries only the missing shared-comparator fix instead of merging the overlapping PR diff.

## Change

`tools/k2_aggregate_vector_audit.compare` now refuses both shorter and longer vectors relative to a positive declared row count, and nonfinite values on either candidate or reference. Previously, `zip` could silently truncate in-memory vectors and emit passing metrics for incomplete evidence.

Added five regression methods, including both invalid sides. The existing `test_k2_aggregate_vector_audit.py` registration in the offline runner and GitHub parity workflow is retained.

## Acceptance

These are source changes and synthetic tests, not GPU measurements. Actual Python suite execution, MSVC/Vulkan replay and independent GGML validation must be performed separately. This audit remains aggregate-only and cannot certify individual-expert stage outputs.

```ini
CERTIFIED_GATES=0
G05=NOT_CERTIFIED
G06=NOT_CERTIFIED
PROMOTE=0
TIP_CLIMB=HOLD
```
