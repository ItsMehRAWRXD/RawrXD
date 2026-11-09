# Worktree materialization

## Expected

Fresh detached worktree at `273924f9…`, complete non-sparse checkout, zero tracked changes, and all 11 runtime files physically present.

## Observed

`G:\~dev\rawrxd-ext-candidate-clean` was unused before creation and was created at the requested commit. During/after creation it reported:

- `TRACKED_CHANGES=301819`
- `core.sparseCheckout` not set in repository config
- `core.sparseCheckoutCone` not set
- `ExtensionHostWorker_main.cpp` physically absent
- all 11 ExtensionHost runtime files physically absent
- worktree administrative state `locked initializing`
- multiple active Git processes still running after a 20-second observation window

Acceptance failed. The new worktree is not trusted and must not receive the ExtensionHost repair.

