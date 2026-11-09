# EXTENSIONHOST_CANDIDATE_WORKTREE_RECOVERY_001 — Git diagnosis

Status: recovery blocked; no source patch, build, or runtime execution performed.

- Repository HEAD: `273924f9f4b0d75ed770559da448164ec632ce00`
- Git version: `2.55.0.windows.3`
- Common Git directory: `G:\~dev\rawrxd\.git`
- Primary tracked changes: 2
- Existing conflicted candidate: `G:\~dev\rawrxd-ext-candidate` (left untouched; `locked initializing`)
- Proposed clean candidate: `G:\~dev\rawrxd-ext-candidate-clean` (also `locked initializing` during checkout)
- Repository config: `core.bare=false`; no repository-level `core.sparseCheckout`, `core.sparseCheckoutCone`, `core.worktree`, or `extensions.worktreeConfig` values observed.
- No common sparse-checkout file was present.

The committed tree contains all 11 ExtensionHost files. Both candidate worktrees nevertheless report approximately 301,819 tracked changes and fail to materialize the files. Active Git checkout processes remain, so the checkout is incomplete or blocked by an external filesystem/index condition. No reset, clean, forced checkout, or repair was attempted.

