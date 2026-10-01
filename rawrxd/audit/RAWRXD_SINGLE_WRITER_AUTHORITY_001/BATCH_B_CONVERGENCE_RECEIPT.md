# RAWRXD_SINGLE_WRITER_AUTHORITY_001 — Batch B (mechanism convergence)

Date: 2026-10-01
Authorization: lease-owner granted to user, 2026-09-30 / 2026-10-01.
Ladder executed: B01 freeze → B02 canonical selection → B03 shared predicate →
B04 bind into build graph → B05 migrate callers → B06 seven required cases →
B07 drift / baseline.

---

## B01 — As-found freeze

```
src/agentmodes/WriterLeaseAuthority.h   lines=130  sha256=072f2d508afe8eb89e285fe3c21194aaa6ac148ace207882fe62fb4b02221165
src/agentmodes/WriterLeaseAuthority.cpp lines=482  sha256=b088d2d971c5efb08096e333be651860d9d2f530c228ba8139507b01a5221c8f
src/authority/SingleWriterAuthority.h   lines=111  sha256=219b846e779d341dd48b1741d6b3107eebd0b901609436b29394f589da3114c7
src/authority/SingleWriterAuthority.cpp lines=400  sha256=a8af4ec80c793c0392721dd0df37a64e46c1827bbdd33d91703236ba8e596174
```

Every reference to the legacy implementation, classified:

| Referrer | Kind | Production? |
|---|---|---|
| `src/ProcessUtil.h:8` | comment | no |
| `tools/single_writer_adversarial_test.cpp` | the test itself | no (test) |
| `evidence/RAWRXD_STUB_RECONCILIATION_001/BATCH_0/lease_tool.cpp:5` | evidence, in no target | no |
| `evidence/.../single_writer_gate.cpp:4,7` | evidence, in no target | no |
| `audit/*.txt`, `*.RECEIPT` | prose | no |

```
LEGACY_IMPL_PRODUCTION_CALLERS=0
```

This is what made convergence safe: there was no production call site to migrate.

## B02/B04 — Canonical implementation selected and bound

`src/authority/SingleWriterAuthority` is canonical, on the evidence:

- the authorized path set is **persisted in the lease file** and round-trips
  through `peekLease`, so a second process reading the lease sees the same scope;
- the lease is published with `MoveFileExW` **without** `MOVEFILE_REPLACE_EXISTING`,
  so a writer that loses the create race fails rather than overwriting a live lease;
- the lease file is `.rawrxd/leases/writer.lease`, confined by construction.

It was previously referenced by **zero** targets. It is now built:

```
CMakeLists.txt:16504  add_library(rawrxd_single_writer STATIC src/authority/SingleWriterAuthority.cpp)
CMakeLists.txt:16536  target_link_libraries(single_writer_adversarial_test PRIVATE rawrxd_single_writer)
-> F:\~dev\rawrxd\build\Release\rawrxd_single_writer.lib
```

The legacy target `rawrxd_writer_lease` was removed from the build graph. Both legacy
**files remain on disk** — nothing was deleted — and are labelled superseded in
`CMakeLists.txt` so a later reader cannot mistake them for the live mechanism.

```
CANONICAL_IMPL=src/authority/SingleWriterAuthority.*
CANONICAL_IMPL_IN_BUILD_GRAPH=1
LEGACY_IMPL_IN_BUILD_GRAPH=0
LEGACY_IMPL_PRODUCTION_CALLERS=0
PROCESS_GLOBAL_AUTHORITY=0
LEASE_PERSISTED_SCOPE=1
LEASE_CREATE_ATOMIC=1
```

## B03 — Pre-write protection moved into the canonical implementation

Added to `SingleWriterAuthority.{h,cpp}`:

```cpp
enum class WriteRefusal { None, NoLease, LeaseOwnerMismatch,
                          PathEscapesRepoRoot, PathOutsideScope };
std::string relativeToRepo(const Lease&, const std::string&);
bool        pathAuthorized(const Lease&, const std::string&);
WriteCheck  checkWrite(const Lease&, const std::string&);
```

`validateStagingScope` was rewritten to call `pathAuthorized`, so the write gate and the
commit gate consume **one** predicate and **one** resolver:

```cpp
while (std::getline(iss, line)) {
    ...
    if (!pathAuthorized(lease, line)) return false;   // same predicate as checkWrite
}
```

`relativeToRepo` compares components, never a text prefix, and skips separator components.
Skipping separators is required and was found by measurement: `fs::path("f:/x")` exposes its
root-directory as `/`, while the same path after `lexically_normal()` exposes it as `\`.
Comparing them literally rejected **every** in-scope path on this drive.

## B05/B06 — Migrated caller and the seven required cases

`tools/single_writer_adversarial_test.cpp` rewritten against the canonical API. The generated
project now compiles exactly one source (`single_writer_adversarial_test.cpp`) and links
`rawrxd_single_writer.lib`.

```
authorized/in-scope file        -> AUTHORIZED_WRITE_ALLOWED=PASS
unauthorized/out-of-scope file  -> UNAUTHORIZED_PATH_WRITE_BLOCKED=PASS
../ traversal                   -> PATH_TRAVERSAL_BLOCKED=PASS  (both ../outside.txt and src/../../outside.txt)
absolute path outside repo      -> OUTSIDE_REPO_BLOCKED=PASS
sibling-prefix collision        -> SIBLING_PREFIX_COLLISION_BLOCKED=PASS  (F:\~dev\.scratch_repo_evil/x.txt)
authorized commit               -> AUTHORIZED_COMMIT_ALLOWED=PASS
unauthorized commit             -> UNAUTHORIZED_STAGED_PATH_BLOCKED=PASS
```

Plus: `LEASE_ACQUIRED_EXCLUSIVELY`, `LEASE_PERSISTED_SCOPE`,
`SECOND_WRITER_ACQUIRE_BLOCKED`, `COMMIT_WITHOUT_LEASE_BLOCKED`,
`COMMIT_AFTER_HEAD_MOVED_BLOCKED`, `FOREIGN_LEASE_RELEASE_BLOCKED`, `STALE_LEASE_RECOVERY`,
`BENEFICIAL_FIX_BYPASS_ATTEMPT_BLOCKED`, `WORKTREE_DRIFT_DETECTABLE`.

## Negative controls — the gate failed four times from real code

1. `AUTHORIZED_WRITE_ALLOWED=FAIL … path does not resolve inside the repository root` →
   `VERDICT=FAIL`, exit 1. Cause: the separator-component defect described above.
2. `UNAUTHORIZED_STAGED_PATH_BLOCKED=FAIL`. Cause: the test staged an **unmodified**
   file, so `git diff --cached` was empty, and an empty set is a subset of every scope —
   the check passed for the wrong reason. Now asserted with `!staged.empty()`.
3. `COMMIT_AFTER_HEAD_MOVED_BLOCKED=FAIL`, `expected == actual`. Cause: `git commit -a`
   does not stage untracked files, so HEAD never moved.
4. `STALE_LEASE_RECOVERY=FAIL`. Cause: `tooOld` is `now - acquired > maxAgeSeconds`; with
   `maxAgeSeconds = 0` a lease written in the same second is not stale. The persisted
   timestamp is now aged explicitly.

Also caught by the compiler during this increment: two `const char* + const char*` pointer
additions in the new test (C2110).

## B07 — Drift vs baseline dirt, kept separate

Your correction is recorded and applied: a dirty worktree is **not** drift.

```
WORKTREE_DRIFT_DURING_GATE_DETECTED=PASS   a mid-gate write IS visible in the fingerprint
WORKTREE_BASELINE_DIRTY_COUNT=161          measured, not inherited from the earlier 135
```

The count moved 135 → 161 because this increment and the previous one added files. Drift
detectability is proven; drift *absence* is a separate property, and it cannot be certified
while the baseline is non-zero.

## Receipt

```ini
GATE=RAWRXD_SINGLE_WRITER_AUTHORITY_001
BATCH=B

CANONICAL_IMPL=src/authority/SingleWriterAuthority.*
CANONICAL_IMPL_IN_BUILD_GRAPH=1
LEGACY_IMPL_PRODUCTION_CALLERS=0
LEGACY_IMPL_FILES_DELETED=0

PREWRITE_AUTHORIZATION=PASS
PRECOMMIT_AUTHORIZATION=PASS
SHARED_PATH_PREDICATE=PASS
PERSISTED_LEASE_SCOPE=PASS

UNAUTHORIZED_PATH_WRITE_BLOCKED=PASS
PATH_TRAVERSAL_BLOCKED=PASS
OUTSIDE_REPO_BLOCKED=PASS
SIBLING_PREFIX_COLLISION_BLOCKED=PASS
AUTHORIZED_COMMIT_ALLOWED=PASS
UNAUTHORIZED_STAGED_PATH_BLOCKED=PASS

WRITE_GUARD_SCOPE=COOPERATING_API_CALLERS_ONLY
OS_SANDBOX=0
DIRECT_NATIVE_IO_BYPASS_POSSIBLE=1

WORKTREE_BASELINE_DIRTY_COUNT=161
WORKTREE_DRIFT_DURING_GATE_DETECTED=PASS
WORKTREE_DRIFT_DURING_GATE=0_NOT_CERTIFIABLE_WHILE_BASELINE_DIRTY

NEGATIVE_TEST_OBSERVED=PASS
STUB_FALLBACKS=0
FAKE_SUCCESS_PATHS=0

VERDICT_DERIVED_FROM_CHECKS=1
HARDCODED_VERDICT=0
VERDICT=FAIL
EXIT_CODE=1
```

## Verdict — every mechanism check passes; the gate still refuses

All 17 mechanism checks print PASS and `SHARED_PATH_PREDICATE=PASS`. The executable still
exits **1** with `VERDICT=FAIL`, for exactly one reason: `WORKTREE_BASELINE_DIRTY_COUNT=161`
and the verdict requires it to be 0.

That is the correct outcome, not a defect. The mechanism is proven and the repository is not
ready to be certified against it.

```
RAWRXD_SINGLE_WRITER_AUTHORITY_001=PARTIAL
VERDICT=NOT_CERTIFIED_PENDING_WORKTREE_RECONCILIATION
```

The single remaining condition is working-tree reconciliation — `Batch B step 6 / B06`, the
`WORKTREE_BASELINE_DIRTY_COUNT=0` row. That is Batch B's reconciliation lane and it has not
been started.

## Still open, deliberately out of this batch

- `RawrXD-AutoFixCLI` — `SOURCE_REAL_IMPLEMENTATION=0`, `MAIN_SYMBOL=0`,
  `CLASSIFICATION=MISSING_IMPLEMENTATION`. Both sources are 24-byte
  `// Auto-generated stub` files. No `main()` will be manufactured to satisfy the linker.
- `regen-ssot-beacons` / `verify-ssot-ext-ownership` — `REFERENCED_SCRIPT_COUNT=3`,
  `SCRIPTS_PRESENT=0`, `SCRIPTS_EVER_COMMITTED=0`,
  `CLASSIFICATION=MISSING_SOURCE_ARTIFACTS`. There is nothing in this repository to restore.
- The legacy `relativeToRepo` in the now-unbuilt `WriterLeaseAuthority.cpp` carries the same
  separator defect. It is retained dead code and is labelled superseded; it was not repaired
  because repairing unbuilt code would not be measured by anything.