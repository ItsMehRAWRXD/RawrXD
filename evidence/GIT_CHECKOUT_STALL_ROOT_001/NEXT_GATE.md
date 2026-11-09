# Next gate

`BASELINE_SOURCE=COMMITTED`  
`CANDIDATE_WORKTREE=UNVERIFIED`  
`CHECKOUT_CLASSIFICATION=CHECKOUT_STILL_PROGRESSING`  
`PATCH_APPLIED=0` · `BUILD=NOT_RUN` · `RUNTIME=NOT_RUN`  
`PROMOTE=0` · `TIP_CLIMB=HOLD` · `CERTIFIED=0`

Allow the currently active checkout processes to finish. Then perform only read-only verification:

1. Confirm no checkout/reset Git process remains.
2. Confirm worktree lock state is no longer `initializing`.
3. Confirm `git status --porcelain` is empty.
4. Confirm all 11 ExtensionHost files exist and match committed object IDs.
5. Confirm frozen SHA remains `748B210A…`.

If the processes stop without completion or produce an explicit error, begin a separate diagnosis of that error. Do not create another worktree or apply either ExtensionHost patch until this gate passes.

