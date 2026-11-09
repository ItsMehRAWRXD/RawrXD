# Checkout completion

Classification: `CHECKOUT_COMPLETE_CLEAN`

- Candidate: `G:\~dev\rawrxd-ext-candidate-clean`
- HEAD: `273924f9f4b0d75ed770559da448164ec632ce00`
- `git status --porcelain --untracked-files=all`: empty (`STATUS_COUNT=0`)
- Worktree lock: no longer present in `git worktree list --porcelain`
- Sparse checkout: no effective `core.sparseCheckout` or `core.sparseCheckoutCone`; no common sparse-checkout file
- Index: present at worktree admin path; 49,540,216 bytes; last modified 2026-11-02 01:41:06
- Candidate source is clean and isolated from dirty primary-tree changes.

The earlier missing-file state was incomplete materialization, not demonstrated source loss or repository corruption.

