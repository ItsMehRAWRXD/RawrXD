# Safe selective integration — current F: working tree

This document is an **integration procedure**, not evidence that the F:
checkout has been modified or that any Windows build has passed.

Verified GitHub source state:
- `local-30b-backend` `src/rawrxd_cli_v2.cpp` lacks
  `RAWRXD_CLI_V2_DISPATCH` and `EMPTY_MODEL_RESPONSE`.
- `feature/deep2-promethevs-native-75` has both.
- Both contain `doctor` dispatch.
- Current F: has uncommitted CLI, Deep2, IDE and terminal changes:
  never hard-reset, clean, force-checkout or bulk cherry-pick.

## Recommended Windows procedure

1. In `F:\rawrxd`, record `git status --porcelain=v1`,
   `git rev-parse HEAD`, and full SHA-256 hashes of modified files.
2. Save a patch of tracked changes via `git diff --binary` and separately
   inventory untracked files. Do not delete or overwrite either.
3. Fetch the integration branch and compare *individual source hunks* using
   `git diff local-30b-backend...origin/feature/deep2-promethevs-native-75 -- src/rawrxd_cli_v2.cpp`.
4. Apply only the dispatch witness and the empty-response failure guard to
   the local source. Preserve concurrent local edits. Inspect the resulting
   diff before building.
5. Stop only conflicting build processes after verifying ownership.
   Use a new isolated build directory to avoid stale binaries and locked
   artifacts. Build `RawrXD-CLI-V2` with one worker.
6. Resolve the exact produced `rawr.exe` path; require one unambiguous
   candidate, capture full SHA-256, build configuration and commit.
7. Run `doctor` and `models` with dispatch tracing enabled, bounded
   execution, captured stdout/stderr, exit code and duration.
8. Classify empty Ollama outputs by model, response status, finish reason,
   streaming frames and timeout; do not report an empty answer as success.
9. Run deterministic Deep2 reference-token parity before GPU TPS testing.
10. Preserve all receipts under `F:\rawrxd\evidence`.

## Explicit stop conditions
- Build cannot finish serially.
- More than one candidate executable without deterministic selection.
- Runtime executable SHA-256 differs from receipt.
- A command prints usage instead of the required diagnostics.
- Model output is empty but reported as successful.
- GPU counters remain zero when GPU execution is claimed.

## Current status
GitHub branch comparison: VERIFIED.
F: selective application: NOT PERFORMED.
Serialized MSVC build: NOT PERFORMED.
CLI runtime certification: NOT PERFORMED.
