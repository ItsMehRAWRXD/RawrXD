# Next gate

`BASELINE_SOURCE=COMMITTED` · `CANDIDATE_WORKTREE=UNVERIFIED`  
`PATCH_APPLIED=0` · `BUILD=NOT_RUN` · `RUNTIME=NOT_RUN`  
`PROMOTE=0` · `TIP_CLIMB=HOLD` · `CERTIFIED=0`

Recovery acceptance failed because a fresh worktree reproduced the 301,819 tracked-change state and did not materialize the 11 committed runtime files. Do not apply `BASELINE_RECOVERY.patch` or the ExtensionHost repair.

Required next action: investigate the active checkout processes, worktree administrative locks, index/worktree configuration, filesystem/filter behavior, and Git process completion. Any repair must be explicitly authorized and must not use destructive reset/clean operations automatically.

