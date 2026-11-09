# Next gate

`CANDIDATE_WORKTREE=CLEAN_BASELINE_VERIFIED`  
`PATCH_APPLIED=1`  
`BUILD=NOT_RUN` · `RUNTIME=NOT_RUN`  
`PROMOTE=0` · `TIP_CLIMB=HOLD` · `CERTIFIED=0`

The source repair is applied and reviewed on `G:\~dev\rawrxd-ext-candidate-clean`. The next action requires separate authorization for a candidate-only compile of the IDE and ExtensionHost, followed by the focused tests in `TEST_READINESS.md`.

Before build authorization, resolve or explicitly accept the `git diff --check` line-ending warnings. Do not modify the frozen executable, primary tree, or promotion state.

