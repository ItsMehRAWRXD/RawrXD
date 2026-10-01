# Single-writer enforcement — Path 2, self-contained canonical authority

## Path 2 decision: accepted, with one correction to the allowlist

The dependency rule is right and the canonical file already satisfies it.

```
WriterLeaseAuthority.cpp
    ├── Win32 process/locking primitives   <windows.h>          ✓
    ├── filesystem                         (transitive)         ✓
    ├── git subprocess/query boundary      (internal)           ✓
    └── private hashing primitive           — not needed        ✓
```

Measured include set of `src/authority/SingleWriterAuthority.cpp` (lines 13–27):
its own header, `<atomic> <chrono> <cstdio> <cstdlib> <cstring> <fstream>
<random> <sstream> <string> <system_error> <thread>`, and `<windows.h>`.

Zero references to `RawrCertAuthority`, `receipt::`, `receiptcheck::`,
`ReceiptAuthority`, `ImmutableReceiptAuthority`, or `RawrGate`. It uses `<random>`
for the nonce and `<atomic>`/`<thread>` for concurrency. **It does not hash**, so a
private BCrypt helper is not required there.

The dependency you asked me to cut exists only in `src/agentmodes/WriterLeaseAuthority.cpp`,
which uses `rawrxd::cert::sha256Bytes` for scope digests. That file is the one
being retired, so the cut becomes moot — **unless** it is kept, in which case the
private BCrypt replacement is required.

> Bootstrap authorities may depend downward on OS/runtime primitives, but must not
> depend upward on the certification systems they are intended to govern.

The canonical implementation honours this today, unprompted.

## The one correction: allowlist slots 1–2 name the wrong file

The stated allowlist is:

```ini
rawrxd/src/agentmodes/WriterLeaseAuthority.h    <- slot 1
rawrxd/src/agentmodes/WriterLeaseAuthority.cpp  <- slot 2
rawrxd/tools/single_writer_adversarial_test.cpp
rawrxd/CMakeLists.txt
```

But `src/authority/SingleWriterAuthority.*` is canonical, and the canonical test
`tools/single_writer_adversarial_test.cpp:31` currently includes
`agentmodes/WriterLeaseAuthority.h`. So as written, the allowlist would have the
**non-canonical** file landing while the **canonical** file is neither allowlisted
nor tested.

This is a swap, not an expansion. Four paths stay four paths:

```ini
rawrxd/src/authority/SingleWriterAuthority.h      <- replaces slot 1
rawrxd/src/authority/SingleWriterAuthority.cpp    <- replaces slot 2
rawrxd/tools/single_writer_adversarial_test.cpp  <- re-pointed at canonical
rawrxd/CMakeLists.txt
```

Everything else — no expansion, no `src/agentmodes/` edit, no `RawrCertAuthority`
change — follows from that swap. **This is the only place I am departing from the
literal instruction, and it is required for the instruction to be self-consistent.**

## Dependency scan — run before compiling

The canonical file must contain no references to:

```
RawrCertAuthority | receipt:: | receiptcheck:: | ReceiptAuthority
ImmutableReceiptAuthority | RawrGate
```

Expected: 0, by the measured include set. The scan is still run, because a scan
that is never executed is an assumption.

## Execution order

```
A  Three-way comparison in scratch repositories
B  Prove every test predicate is measured, not printed
C  Prove the canonical authority exists in a real built target
D  Single-process conductor transaction
E  Measure Git bypass classes individually
F  Source/build/adoption provenance requirements
   → RAWRXD_SINGLE_WRITER_AUTHORITY_001 verdict
```

**A — Three-way comparison.** Re-point `tools/single_writer_adversarial_test.cpp`
at `src/authority/`, port across the scenarios proven against the agentmodes
variant (exclusive acquire via `CREATE_NEW`, PID-reuse-vs-recycled-PID liveness,
foreign release by nonce and by pid, scope-expansion refusal), then run both
`tools/single_writer_adversarial_test.cpp` and
`tests/test_single_writer_authority.cpp` against scratch repos. Record builds,
passes, target membership, tracking.

Measure the contradiction at `docs/RECONCILIATION_MIGRATION_BATCH_1_001.md:20`
(`WRITER_LEASE_IMPLEMENTED=0`) against the built `rawrxd_single_writer_authority.lib`
and **record it in test output only**. `docs/` is not one of the four authorized
paths, so the correction is deferred to a later lease-governed batch:

```ini
DOCUMENTATION_CONTRADICTION_MEASURED=1
DOCUMENTATION_CORRECTION_DEFERRED=1
DOC_EDIT_IN_THIS_BATCH=0
ALLOWLIST_EXPANSION=FORBIDDEN
```

**B — Predicates must be measured.** `beneficialFixBypassAttemptBlocked` exists only
in the agentmodes driver today; it must exist in the canonical result. Any predicate
printed as a literal invalidates the run — that is precisely the
`test_receipt_immutability.cpp:143-146` shape.

**C — Adoption.** Confirm `SingleWriterAuthority.cpp` is in a real target and
verify by symbol resolution in the built binary, not by reading `CMakeLists.txt`.

**D — Conductor, single process.**

```ini
rawr conductor run --paths <p...> --allow <p...> --message "<m>"
CONDUCTOR_ENFORCED_MODE=SINGLE_PROCESS_TRANSACTION
```

Acquire → stage → authorize → commit → release under one process identity. Fail
closed in the frozen order: ownership → HEAD → staging scope → authorize → commit.
`stage` rejects unauthorized paths **before** `git add`; assert the index is
byte-identical before and after a refusal.

Token-based `acquire|stage|commit|release --lease-id` may exist only behind
`--assurance=token`, stamped `AUTHORITY=TOKEN_CAPABILITY_LOWER_ASSURANCE`.

**E — Bypass taxonomy, measured individually.**

```ini
NORMAL_DIRECT_GIT_COMMIT_BLOCKED
NO_VERIFY_BYPASS_BLOCKED
HOOK_RECONFIGURATION_BLOCKED
DIRECT_REF_MUTATION_BLOCKED      (update-ref, commit-tree)
PUSH_POLICY_ENFORCED
REPOSITORY_WIDE_ENFORCEMENT=0    until every one is measured
```

**F — Provenance requirements.** RawrGate must refuse to certify a gate whose
backing source is untracked or absent from a build target. This generalises
`sourceBackingChecked` and retrospectively blocks the retracted false PASS.

## Acceptance sequence

The stated precondition must be re-verified at execution time, not assumed — HEAD
has moved four or more times in this session, so a precondition quoted from an
earlier turn is exactly the "wrong provenance" failure this gate exists to prevent.

```
HEAD == a078e3b87  (re-verify)
origin == a078e3b87  (re-verify)
staged == 0  (re-verify)
    → forbidden-dependency scan == 0
    → compile canonical test from source (SingleWriterAuthority.cpp
                                       + single_writer_adversarial_test.cpp
                                       + bcrypt.lib)
    → execute canonical test
    → 17/17 required, freshly generated
    → HEAD recheck
    → stage exactly the four canonical paths
    → staged-scope validation
    → HEAD recheck
    → bootstrap commit
```

The previous 17/17 does **not** count. It was produced by the agentmodes variant
against a different source revision that was later edited externally.

## Classification carried forward

```ini
W8_IMMUTABLE_API_ADOPTION=IMPLEMENTED      (W8LifecycleAuthority.cpp:32, main_win32.cpp:1933)
W8_CERTIFICATION=BLOCKED

RECEIPT_IMMUTABILITY_TEST=LIVE_FALSE_PASS_EMITTER
RECEIPT_IMMUTABILITY_CERTIFICATION=RETRACTED

SINGLE_WRITER_CANONICAL_IMPL=src/authority/SingleWriterAuthority.*
SINGLE_WRITER_CANONICAL_DEPENDENCY_CLEAN=1
SINGLE_WRITER_MECHANISM_STATUS=REQUIRES_PHASE_A_B_RECONFIRMATION
SINGLE_WRITER_ENFORCEMENT_STATUS=NOT_COMPLETE

CONDUCTOR_ENFORCED_MODE=SINGLE_PROCESS_TRANSACTION
TOKEN_MODE=LOWER_ASSURANCE

MECHANISM_17_OF_17=necessary_not_sufficient
CMAKE_ADOPTION=required
CONDUCTOR_TRANSACTION=required
GIT_BYPASS_ENFORCEMENT=required

NEXT_PHASE=A_THREE_WAY_COMPARISON
GPU=BLOCKED
STRICT_CERT=NOT_COMPLETE
```

Two facts coexist and neither overwrites the other: W8 adopted the immutable API,
**and** the immutability regression can still literally print `VERDICT=PASS`.

## `rawr run` — separate lane, closed, no receipt

`rawr run` is operational and is **not** gated by any of this work:

```ini
RAWR_RUN_RUNTIME=WORKING
MODEL_RESOLUTION=PASS          MODEL_LOAD=PASS
TOKENIZATION=PASS             GENERATION=PASS
STREAMING=PASS
CPU_GENERATION=PROVEN
OBSERVED_TPS=0.496            # observed, not a target and not proven optimal
GPU_REQUIRED=0
WRITER_LEASE_REQUIRED=0
W8_REQUIRED=0
STRICT_CERT_REQUIRED=0
RAWR_RUN_CERTIFICATION_RECORD=DEFERRED
```

No `RAWRXD_RAWR_RUN_001` receipt is created in this batch — a successful runtime
test must not become another repository mutation while the bootstrap is
unresolved. The execution evidence stands on its own for now.

Remaining known runtime defect, registered not scheduled: `resolveModelPath` at
`src/deep2/rawrxd_run_modelname_001.cpp:269,305` matches by case-insensitive
substring on the filename stem and returns the first hit, with no exclusion of
`ggml-vocab-*.gguf` tokenizer files and no deterministic ordering. Bare names can
therefore resolve to a vocab, or to different files across runs.

## Bootstrapping gate

Any failure before the final commit yields `BOOTSTRAP_COMMIT_ALLOWED=0` and
`VERDICT=HOLD` — not a licence to add a fifth dependency.

```ini
PRE-FLIGHT      HEAD==expected  origin==expected  staged==0
      ▼
DEPENDENCY SCAN forbidden refs == 0
      ▼
CANONICALIZE    driver includes authority/SingleWriterAuthority.h; scenarios ported
      ▼
SCRATCH TESTS   both drivers; all predicates measured
      ▼
BUILD ADOPTION  canonical .cpp linked; symbol presence verified
      ▼
HEAD CHECK
      ▼
STAGE           exactly four canonical paths
      ▼
STAGING-SCOPE CHECK
      ▼
HEAD CHECK
      ▼
BOOTSTRAP COMMIT
```

## Path 2 — closed

```ini
PATH_2_DECISION=CLOSED
CANONICAL_IMPL=rawrxd/src/authority/SingleWriterAuthority.*
CANONICAL_TEST_DRIVER=rawrxd/tools/single_writer_adversarial_test.cpp
ALLOWLIST_COUNT=4
ALLOWLIST_EXPANSION=FORBIDDEN
RAWRCERT_DEPENDENCY=0
RECEIPT_DEPENDENCY=0
RAWRGATE_DEPENDENCY=0
AGENTMODES_WRITER_LEASE=NON_CANONICAL_PRESERVED_UNDER_NO_DELETIONS
PREVIOUS_17_OF_17=NON_AUTHORITATIVE
FRESH_CANONICAL_TEST_REQUIRED=1
BOOTSTRAP_COMMIT_ALLOWED=0_UNTIL_ACCEPTANCE_SEQUENCE_COMPLETES
```

## Hard scope boundary

This batch does **not** absorb: GPU, W8 certification, receipt migration, duplicate
cleanup, Puppeteer, dump-count reconciliation, QuickJS, or any other registered
defect. Those are recorded, not scheduled — preserved without becoming scope creep.

Outstanding uncommitted inventory remains under the standing `NO_DELETIONS` rule:
`src/agentmodes/WriterLeaseAuthority.*`, `src/agentmodes/ImmutableReceiptAuthority.*`,
`src/agentmodes/friends/`, the `RawrCertAuthority` sha256Bytes change, the other
writer's `RawrDumpAuthority.cpp` / `ModelCatalogAuthority.*` edits,
`RawrDumpAuthority.cpp.new`, and the dirty `3rdparty/quickjs` submodule.
