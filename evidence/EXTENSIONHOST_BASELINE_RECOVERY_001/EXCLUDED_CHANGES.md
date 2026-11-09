# Excluded changes

Excluded from baseline recovery:

- All unrelated dirty-primary changes outside the 11-file runtime closure.
- All generated artifacts, build outputs, object files, binaries, logs, and evidence receipts.
- The frozen executable and all candidate executables.
- The broader `e61f51a86b` synchronization commit changes; it contains many unrelated Win32IDE modifications and is not a baseline patch.
- Any current candidate worktree deletion/untracked state; that is checkout corruption, not source provenance.
- New handshake, quoting, launch-error, and graceful-shutdown changes from `EXTENSIONHOST_INTEGRATION_REPAIR_001`; those belong to the subsequent repair stage, not baseline recovery.

