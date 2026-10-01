# RAWRXD_SINGLE_WRITER_AUTHORITY_001 — Batch A increment

Date: 2026-10-01
Authorization: lease-owner granted to user, 2026-09-30 / 2026-10-01.
Scope of edits: `src/agentmodes/WriterLeaseAuthority.{h,cpp}`,
`tools/single_writer_adversarial_test.cpp`.

---

## 1. Measured starting state

`tools/single_writer_adversarial_test.cpp` already existed, already linked, and already
passed 8 checks on `F:\~dev`:

```
LEASE_ACQUIRED_EXCLUSIVELY=PASS        SECOND_WRITER_ACQUIRE_BLOCKED=PASS
COMMIT_WITHOUT_LEASE_BLOCKED=PASS      COMMIT_AFTER_HEAD_MOVED_BLOCKED=PASS
UNAUTHORIZED_STAGED_PATH_BLOCKED=PASS  FOREIGN_LEASE_RELEASE_BLOCKED=PASS
STALE_LEASE_RECOVERY=PASS              BENEFICIAL_FIX_BYPASS_ATTEMPT_BLOCKED=PASS
VERDICT=PASS  EXIT_CODE=0
```

Two of the eight declared acceptance criteria had **no corresponding capability and no
corresponding check**:

```
UNAUTHORIZED_PATH_WRITE_BLOCKED=1     -> no implementation existed
WORKTREE_DRIFT_DURING_GATE=0          -> no implementation existed
```

The gap was real, not cosmetic. `checkCommit` refuses an out-of-scope path only at *commit*
time. Between the write and the commit there is a window in which a second writer has already
modified a file it was never authorized to touch, and the damage is done even though the
commit is later refused.

## 2. `LEASE_MECHANISM_SPLIT` — located, NOT resolved

The audit recorded `LEASE_MECHANISM_SPLIT=1` without saying where the second mechanism was. It
is located now. **Two complete implementations of the same authority exist:**

| | `src/agentmodes/WriterLeaseAuthority.{h,cpp}` | `src/authority/SingleWriterAuthority.{h,cpp}` |
|---|---|---|
| Lines | 537 | 400 |
| Lease file | `writer.lease` | `.rawrxd/leases/writer.lease` |
| In a CMake target | **yes** — `rawrxd_writer_lease` | **no** — 0 references in any `CMakeLists.txt` |
| `authorized_paths` in the lease record | no (process-global `g_authorized`) | yes (persisted in the lease JSON) |
| Publish protocol | `CreateFileA(CREATE_NEW)` | `MoveFileExW` without `MOVEFILE_REPLACE_EXISTING` |
| Own test | `tools/single_writer_adversarial_test.cpp` | `test_single_writer_authority.cpp` |

The richer implementation is the unbound one. This is stated here as a measured finding and
**not** resolved in this increment: collapsing the two requires deciding which lease file
format is canonical and migrating callers, and deleting either one would remove completeness,
which is out of scope here. It is the first item of the next increment.

## 3. Added: write-time scope enforcement

`WriterLeaseAuthority.h/.cpp` gained:

```cpp
enum class WriteRefusal {
    None, NoLease, LeaseOwnerMismatch, LeaseExpired,
    PathEscapesRepoRoot, PathOutsideScope
};
WriteCheck checkWrite(repoRoot, held, relPath);
std::string relativeToRepo(repoRoot, relPath);
bool pathAuthorized(path);
```

Scope and lease rules are identical to `checkCommit`, factored into shared predicates
(`leaseIsOurs`, `leaseExpired`) so the two gates cannot drift apart. `relativeToRepo` is a
textual normalized-prefix comparison rather than `fs::equivalent`, because an authorized path
is checked *before* it is written and therefore need not exist yet.

**Stated precisely, because it is weaker than the criterion's name suggests:** this is an
API-level guard, not an OS sandbox. A process that calls `fopen` directly still bypasses it.
What it guarantees is that every write performed *through the authority* is authorized at the
moment it happens, and that the check-to-write window is now the only remaining window.

## 4. Added: worktree drift detection across a gate window

`testWorktreeDriftDuringGate` fingerprints `HEAD` + `git status --porcelain`, runs the commit
gate, injects a foreign write mid-window, and asserts the fingerprint changed. It fails if the
drift is invisible.

Note the direction of the result: this proves **drift is detectable**, not that drift is zero.
The live repository currently has 135 dirty entries, so
`WORKTREE_DRIFT_DURING_GATE=0` is **not** established for this repository. That value belongs
to Batch B (working-tree reconciliation), not to Batch A.

## 5. Negative control

The gate is proven able to fail. The first run of the new tests produced, from real code:

```
UNAUTHORIZED_PATH_WRITE_BLOCKED=FAIL detail=in-scope write was refused: path does not resolve
                                inside the repository root: src/agentmodes/WriterLeaseAuthority.cpp
LEASE_SCOPE_ACTUALLY_ENFORCED=FAIL
VERDICT=FAIL    EXIT_CODE=1
```

Cause: `relativeToRepo` compared path components without advancing the root iterator, so any
path with depth above the root returned empty. It was fixed by comparing component-by-component
against `root.begin()..root.end()` and rejecting `..` in the remainder.

A second failure was also obtained by construction: `writeFile` used before its declaration
(C3861), and `initScratch` originally created an *empty* repo, so the scope tests reasoned about
a path that did not exist and `git checkout --` failed to restore it. The scratch repo now
creates and commits both the authorized and unauthorized files, so the write-time and drift
tests exercise real paths.

## 6. Final measured result

```
EXIT_CODE=0
GATE=RAWRXD_SINGLE_WRITER_AUTHORITY_001

LEASE_ACQUIRED_EXCLUSIVELY=PASS
SECOND_WRITER_ACQUIRE_BLOCKED=PASS
COMMIT_WITHOUT_LEASE_BLOCKED=PASS
COMMIT_AFTER_HEAD_MOVED_BLOCKED=PASS
UNAUTHORIZED_STAGED_PATH_BLOCKED=PASS
UNAUTHORIZED_PATH_WRITE_BLOCKED=PASS
FOREIGN_LEASE_RELEASE_BLOCKED=PASS
STALE_LEASE_RECOVERY=PASS
BENEFICIAL_FIX_BYPASS_ATTEMPT_BLOCKED=PASS
WORKTREE_DRIFT_DURING_GATE_DETECTED=PASS
LEASE_SCOPE_ACTUALLY_ENFORCED=PASS
VERDICT_DERIVED_FROM_CHECKS=1
HARDCODED_VERDICT=0
VERDICT=PASS
```

`LEASE_SCOPE_ACTUALLY_ENFORCED` is the conjunction of the two scope gates — write-time and
commit-time. Either alone leaves a window.

## 7. Ledger

```
ONE_CANONICAL_LEASE_MECHANISM=0     two implementations exist; the richer one is unbound
SECOND_WRITER_ACQUIRE_BLOCKED=1
UNAUTHORIZED_PATH_WRITE_BLOCKED=1    capability added and measured this increment
COMMIT_WITHOUT_LEASE_BLOCKED=1
COMMIT_AFTER_HEAD_MOVED_BLOCKED=1
FOREIGN_LEASE_RELEASE_BLOCKED=1
LEASE_SCOPE_ACTUALLY_ENFORCED=1
WORKTREE_DRIFT_DURING_GATE_DETECTED=1
WORKTREE_DRIFT_DURING_GATE=0        NOT established; 135 dirty entries, Batch B
GATE_CHECKS=10
GATE_NEGATIVE_CONTROL=FAIL_AS_EXPECTED
RAWRXD_SINGLE_WRITER_AUTHORITY_001=PARTIAL
VERDICT=NOT_CERTIFIED_PENDING_MECHANISM_MERGE
```

**This gate is NOT certified.** `ONE_CANONICAL_LEASE_MECHANISM=0` is a hard blocker: while two
implementations of one authority exist, a call site can bind to either and the guarantee is
ambiguous. The next increment must merge them before this gate can be claimed.