# Next gate

`NEXT_PRIORITY=WORKTREE_RECREATION_OR_REPAIR`  
`BASELINE_RECOVERY=BLOCKED_BY_WORKTREE_MATERIALIZATION`  
`PATCH_APPLIED=0` · `BUILD=NOT_RUN` · `RUNTIME=NOT_RUN`  
`PROMOTE=0` · `TIP_CLIMB=HOLD` · `CERTIFIED=0`

The required source closure is already in candidate Git HEAD; no selective source extraction is justified yet. The next authorized action is to create a clean candidate worktree from `273924f…` with sparse checkout disabled or explicitly populated, then verify the 11-file closure and CMake files from Git. Do not copy from the dirty primary and do not apply the ExtensionHost repair until that clean-baseline verification succeeds.

