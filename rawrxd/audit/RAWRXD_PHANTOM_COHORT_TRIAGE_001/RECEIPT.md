# RAWRXD_PHANTOM_COHORT_TRIAGE_001

**Status: OPEN — no retirement authority granted. `FINAL_VERDICT=PENDING`.**

Tranche 2. This document governs the ~20-file cohort in `WIN32IDE_SOURCES` that is
appended as bare source paths and then subtracted by a later `list(REMOVE_ITEM)`.

---

## 1. Governing rule

```ini
NO_HISTORY          != NEVER_HAD_CODE
NO_LIVE_CONSUMER    != SAFE_TO_RETIRE
LINK_NEUTRAL        != HISTORICALLY_IRRELEVANT

CURRENT_BUILD_IMPACT=MEASURED_BY_CMAKE_MEMBERSHIP
CURRENT_CONSUMERS=MEASURED_BY_LIVE_REFERENCES
RETIRE_OR_RECOVER=DECIDED_BY_HISTORY
FINAL_VERDICT=PENDING_UNTIL_HISTORY_TRIAGE
```

The three `!=` lines are the whole point of this tranche. Each one is a specific inference
that has already been made somewhere in this project's audit trail and been wrong.

```ini
ACTION_PRIORITY_1=ESCALATE_LIVE_CONSUMER
ACTION_PRIORITY_2=RECOVER_HISTORICAL_IMPLEMENTATION
ACTION_PRIORITY_3=REWIRE_TO_LIVE_TWIN
ACTION_PRIORITY_4=KEEP_INTENTIONAL_PLACEHOLDER
ACTION_PRIORITY_5=RETIRE_SAFE_STUB
```

Retirement is the **last legal action**, not the default and not the fallback. Any triage
that reaches `RETIRE` without having first produced and cleared the other four actions is
out of order, regardless of how the history query answered.

The three are independent axes and none substitutes for another. Concretely, this
sequence has been rejected as an argument, because the cohort's own audit already made
it:

```text
"not currently linked"  ->  "never mattered"
```

That inference is false. It is the exact error that let `RAWRXD_STUB_RECONCILIATION_001`
describe this cohort as inert.

## 2. Correction to the standing claim

`RAWRXD_STUB_RECONCILIATION_001` / `STUB_CENSUS.md` classifies this cohort as:

```text
comment-only stubs inside a library source list (link-neutral, zero impact)
```

That description is wrong on its face. These are not comments in a source list. They are
**bare source paths**:

```ini
CMAKE_PATTERN=BARE_APPEND_THEN_REMOVE
SOURCE_PATH_IS_REAL=1        # the path resolves to a real file on disk
SOURCE_BODY_IS_STUB=1        # whose contents are a one-line tombstone
BUILD_GRAPH_STATUS=STRIPPED_LATER
```

The distinction matters. An imaginary reference is a bookkeeping error. A real path that
the build system had to **explicitly subtract** is **stale build intent** — someone once
believed this translation unit was required, and the subtraction is the scar of that
belief. The subtraction makes the entry link-neutral today. It does not make it
meaningless, and it does not retroactively remove the question of what the file was
supposed to be.

This claim is to be narrowed or retracted once triage completes, not before.

## 3. Buckets

Each file resolves to exactly one. `SAFE_TO_RETIRE` is true **only** for `BUCKET_A`.

```ini
BUCKET_A_RETIRE_SAFE
    Every one of these must hold. Missing any one leaves the file PENDING, not Bucket A.
    CURRENT_BODY_CLASS=PURE_STUB
    LIVE_CONSUMERS=0
    EVER_HAD_REAL_CONTENT=NO
    RENAME_GUARD_COMPLETED=YES
    SAME_BASENAME_OR_SYMBOL_TWIN=NO
    INTENTIONAL_PLACEHOLDER=NO
    SAFE_TO_RETIRE=YES

BUCKET_B_RECOVER_CANDIDATE
    pure stub now, git history shows a prior real implementation
    -> RECOVERY outranks every retirement in this cohort

BUCKET_C_KEEP_PLACEHOLDER_WITH_EXPLANATION
    the stub is an intentional documented placeholder and something references it
    (a future target, a feature flag, a guarded source list)
    -> annotate; do not silently retire

BUCKET_D_ESCALATE
    a live consumer exists, or the CMake removal is masking a genuinely missing
    implementation, or retirement would hide a broken integration
    -> do not touch; hand to the owning lane
```

## 4. Per-file receipt

One block per file, in the cohort's order.

```ini
FILE=
EXISTS_ON_DISK=
CURRENT_BODY_CLASS=PURE_STUB|PARTIAL_STUB|REAL_CODE|MISSING
LINE_COUNT=
HEADER_EXISTS=
CMAKE_APPEND_LINE=
CMAKE_REMOVE_LINE=
CMAKE_PATTERN=BARE_APPEND_THEN_REMOVE|OTHER
LIVE_REFERENCES=
LIVE_CONSUMERS=
HISTORY_CHECKED=
HISTORY_CONFIDENCE=PROVEN_ABSENT|PROVEN_PRESENT|INCONCLUSIVE|UNAVAILABLE
EVER_HAD_REAL_CONTENT=
  -- and if YES, classify WHICH of these it was:
HISTORY_CONTENT_CLASS=REAL_IMPLEMENTATION|GENERATED_EMPTY_STUB|COMMENT_ONLY_PLACEHOLDER|RENAMED_OR_MOVED_IMPLEMENTATION|UNKNOWN
LAST_REAL_COMMIT=
LAST_REAL_SUMMARY=

RENAME_GUARD_COMPLETED=YES|NO
SAME_BASENAME_OR_SYMBOL_TWIN=YES|NO|UNKNOWN
TWIN_PATH=
TWIN_STATUS=REAL_CODE|STUB|MISSING|UNKNOWN
ACTION_IF_TWIN_FOUND=REWIRE|ESCALATE|IGNORE

INTENTIONAL_PLACEHOLDER=YES|NO
RECOVERY_CANDIDATE=
SAFE_TO_RETIRE=
ACTION=RETIRE|RECOVER|REWIRE|KEEP|ESCALATE|NONE_YET
```

`TWIN_PATH` / `TWIN_STATUS` exist so that "tree search done" cannot be recorded as a
receipt line. It forces a concrete path and a classification, and it distinguishes a real
implementation twin from another tombstone copy. A twin that is itself a stub is not a
twin; `TWIN_STATUS=STUB` means the search found nothing and the answer remains open.

Load-bearing fields, in order of authority: `EVER_HAD_REAL_CONTENT`, `LIVE_CONSUMERS`,
`ACTION`. Everything else is supporting evidence.

### 4.1 The rename guard — why `EVER_HAD_REAL_CONTENT=NO` is not self-sufficient

`git log --follow` is not reliable across renames or copies. A file that arrived as a
copy of another, or that was renamed on the way in, can report *no history at all* while
its content demonstrably exists under a different path. In that case the correct action is
neither RETIRE nor RECOVER:

```ini
ACTION=REWIRE    # point the source seat at the moved implementation
```

Treating `git log --follow` as authoritative would classify those files as `BUCKET_A` and
retire them, which is how a real implementation gets deleted by a tool that reported it as
absent. Required second pass for every `BUCKET_A` candidate:

- `git log --follow --name-status -- <path>` and `--diff-filter=R` to expose renames.
- `git log --all --diff-filter=A -- '*Similar*Name*'` for the candidate's base name.
- A tree search for a same-basename or same-symbol implementation elsewhere in the repo.
  A file reported as having no history but having a live twin elsewhere is a REWIRE, not
  a retirement.

## 5. Worst-case layer — uncertainty must never resolve to RETIRE

This is the layer that exists purely for the bad case. It is not a fallback; it is the
reason the fields above are separated from the decision.

History can fail to prove absence in ways that are *indistinguishable from* absence at the
level of a boolean:

```text
the file was created by a mass-deletion commit and never had content   -> PROVEN_ABSENT
the file was copied in, so --follow sees only the copy's birth          -> PROVEN_ABSENT (wrong)
the path was renamed on the way in and --follow lost the thread         -> PROVEN_ABSENT (wrong)
the file was never tracked, so there is no history to query             -> PROVEN_ABSENT (wrong)
shallow clone, history truncated                                      -> PROVEN_ABSENT (wrong)
```

Every one of the last four produces the same empty result as the first, and every one of
them can be a real implementation. A boolean `EVER_HAD_REAL_CONTENT=NO` cannot tell them
apart. That is why `HISTORY_CONFIDENCE` is a separate field and why `ACTION=RETIRE`
requires `HISTORY_CONFIDENCE=PROVEN_ABSENT` **and** `RENAME_GUARD_COMPLETED=YES` **and**
`SAME_BASENAME_OR_SYMBOL_TWIN=NO`.

### 5.1 Decision layer

Reliability gates are evaluated BEFORE positive findings. If the history/twin machinery is
unreliable, its positive conclusions are no more trustworthy than its negative ones, and an
action is only legal once the machinery that produced it is itself certified.

```ini
1. LIVE_CONSUMERS > 0                      -> ACTION=ESCALATE
2. CURRENT_BODY_CLASS != PURE_STUB         -> ACTION=KEEP_OR_ESCALATE
3. RENAME_GUARD_COMPLETED = NO             -> ACTION=PENDING_UNRELIABLE
4. ROUND2_TWIN_CHECK_RELIABLE = NO         -> ACTION=PENDING_UNRELIABLE
5. HISTORY_CONFIDENCE <> PROVEN_ABSENT     -> ACTION=PENDING_UNRELIABLE
6. LIVE_TWIN_RICHER = YES                  -> ACTION=REWIRE
7. HISTORY_REAL_CONTENT = YES              -> ACTION=RECOVER
8. INTENTIONAL_PLACEHOLDER = YES           -> ACTION=KEEP
9. otherwise                               -> ACTION=RETIRE_ELIGIBLE
```

Ordering note: the body check runs second, immediately after the consumer check and ahead of
every retrievability test. A real implementation must never be evaluated for retrievability,
because it is not a removal candidate at all.

### 5.1 Positive findings are recorded even when the action is PENDING

Gating reliability first is strictly safer, but it has one cost: a real observation can be
overwritten by an uncertainty label. A file with an observed richer twin in an incomplete
guard would be recorded `PENDING_UNRELIABLE`, and the fact that a richer twin was *seen*
would be lost from the ledger.

So the two are recorded separately. The uncertainty governs the `ACTION`; it does not erase
the evidence:

```ini
ACTION=PENDING_UNRELIABLE
POSITIVE_FINDING_PRESENT=REWIRE_CANDIDATE|HISTORICAL_CONTENT_PRESENT|NONE
POSITIVE_FINDING_EVIDENCE=<path or sha that was observed>
```

`PENDING_UNRELIABLE` means "no action authorised", not "nothing found". Anything observed is
carried forward so a later round can act on it without repeating the search.

```ini
WRONG_ZERO_AUTHORIZES_DELETE=FORBIDDEN
```

The single dangerous output of this process is a clean zero from a check that was not
actually performed. Any agent reporting a twin count must be able to say how it searched;
an unverified `0` is treated as `PENDING_UNRELIABLE`, never as permission.

### 5.2 What KEEP means concretely

`KEEP` is not a deferral that leaves the file looking like live work. The tombstone is
replaced with a comment block carrying its own measurement — the same treatment tranche 1
applied to `Deep2Server_Sovereign.cpp`. That makes the build graph honest without deleting
anything, and it is fully reversible:

```text
RESTORE = git -C F:/~dev checkout HEAD -- <path>
```

So the worst case degrades to *documentation*, never to *data loss*. A file that cannot be
proven inert is still allowed to stop lying about itself.

## 6. Action ordering

Fixed. Deviating from this order is a protocol error, not a judgement call.

```text
1. Complete read-only history triage.
2. Freeze the cohort with hashes and paths.
3. REWIRE / RECOVER anything with historical or moved content. FIRST.
4. Only then retire BUCKET_A pure stubs.
5. Narrow or retract the RAWRXD_STUB_RECONCILIATION_001 "link-neutral" claim.
6. Run build-graph equivalence after any edit.
```

```ini
RECOVERY_CANDIDATES_OUTRANK_RETIREMENTS=YES
```

A file that once held real implementation is not cleanup debris. It is possible source
loss until proven otherwise.

## 6. Cohort summary

```ini
RAWRXD_PHANTOM_COHORT_TRIAGE_001

COHORT_FILES_TOTAL=
PURE_STUB_CURRENT=
BARE_APPEND_THEN_REMOVE=
LIVE_CONSUMER_COUNT=
BUCKET_A_RETIRE_SAFE=
BUCKET_B_RECOVER_CANDIDATE=
BUCKET_C_KEEP_PLACEHOLDER=
BUCKET_D_ESCALATE=
REWIRE_CANDIDATE=

SAFE_TO_RETIRE_COUNT=        # must equal BUCKET_A minus any rename-guard retractions
RECOVERY_CANDIDATE_COUNT=
KEEP_PLACEHOLDER_COUNT=
ESCALATE_COUNT=

FINAL_VERDICT=PENDING|RETIRE_BATCH_SAFE|RECOVERY_REQUIRED|MIXED_ACTION
```

`SAFE_TO_RETIRE_COUNT` is only permitted to be non-zero once every one of its members has
survived the §4.1 rename guard.

## 7. Ledger

```ini
TRANCHE_1_SOURCE_LEVEL=CLOSED
TRANCHE_1_RUNTIME_EVIDENCE=QUEUED
TRANCHE_2_SCOPE=OPEN
PHANTOM_COHORT_RETIREMENT_AUTHORITY=NOT_GRANTED
RECOVERY_CANDIDATES=UNKNOWN
FINAL_VERDICT=PENDING
```

## 8. Triage round 1 — measured

Read-only history triage, cohort of 20. Method recorded: `git log --follow` per file, then
`git ls-tree -r` to resolve the real path at each revision, then `git show <sha>:<path>` for
line count at every revision. Excluded from reference counting: `evidence/`, `audit/`,
`_n2_stage/`, `*.bak`, `build*/`, root-level `*.txt`/`*.csv` dumps.

### 8.1 The escape — one file was never a stub

```ini
FILE=src/deep2/deep2_end_to_end_bench.cpp
CURRENT_BODY_CLASS=REAL_CODE
LINE_COUNT=411
PURE_STUB=NO
REVISIONS=3
EVER_HAD_REAL_CONTENT=YES
  93ef24fd0  A   1 line   (created as stub)
  3523edf14  M   372 lines (real implementation)
  13be5e85d  M   372 lines
HISTORY_CONTENT_CLASS=REAL_IMPLEMENTATION
HEADER_EXISTS=NO
LIVE_CONSUMERS=0
CMAKE_APPEND_LINE=7264
CMAKE_REMOVE_LINE=7416
CMAKE_PATTERN=BARE_APPEND_THEN_REMOVE + OWN_TARGET
OWN_TARGET=add_executable(deep2_end_to_end_bench) @ CMakeLists.txt:11725
OWN_TARGET_GATE=option(BUILD_DEEP2_END_TO_END_BENCH "..." OFF)
RECOVERY_CANDIDATE=YES
SAFE_TO_RETIRE=NO
ACTION=NONE_EXCLUDE_FROM_COHORT
```

Verified independently, not taken on the triage's word: the file's first lines are a real
banner and it includes `Deep2Engine.h`, `TimeReverseDigest.hpp`, `Beaconism.hpp`. And
`CMakeLists.txt:11721` carries the comment *"Replaces the stubbed deep2_end_to_end_bench.cpp
with a real event-driven streaming harness."*

**This file entered the cohort only because it shares the append-then-`REMOVE_ITEM` block.**
Applying `BARE_APPEND_THEN_REMOVE => phantom => retire` would have deleted a working
411-line harness that has its own executable target definition. It is `BUCKET_D` in effect:
`CMAKE_PATTERN` alone is not an identity for "this is a stub".

Revised rule, added as a consequence:

```ini
CMAKE_PATTERN=PHANTOM   !=   CURRENT_BODY_CLASS=PURE_STUB
CHECK_THE_BODY_FIRST_THE_PATTERN_SECOND
```

Recorded as a reusable guard rather than a one-off correction:

```ini
ESCAPE_CASE_PRESENT=1
ESCAPE_CASE_FILE=src/deep2/deep2_end_to_end_bench.cpp
ESCAPE_CASE_CLASS=REAL_HARNESS_IN_PHANTOM_CMAKE_COHORT
LESSON=BUILD_GRAPH_PATTERN_IS_NOT_BODY_CLASS
```

Why this class of near-miss is the dangerous one, and why no build would have caught it:

```ini
PHANTOM_PATTERN_MATCHED=1
CURRENT_BODY_CLASS=REAL_HARNESS
RETIREMENT_ACTION_WOULD_HAVE_BEEN_DESTRUCTIVE=1
BUILD_FAILURE_WOULD_NOT_HAVE_REVEALED_IT=1
```

The file was already stripped from `WIN32IDE_SOURCES`, so deleting it breaks nothing in the
current build. Deletion would have been **silent, unrecoverable from the build, and invisible
in CI** — source loss with no failing build. This is the failure mode a build-verification
discipline structurally cannot detect, which is why the body check has to precede it.

The old inference is now formally invalid, in both directions:

```ini
PHANTOM_PATTERN -> LINK_NEUTRAL   # possibly true
PHANTOM_PATTERN -> SAFE_TO_RETIRE # FALSE, disproved
PHANTOM_PATTERN -> PURE_STUB      # FALSE, disproved
```

### 8.2 The 19 remaining candidates

All 19 are identical in every measured dimension:

```ini
CURRENT_BODY_CLASS=PURE_STUB
LINE_COUNT=1
REVISIONS=5
EVER_HAD_REAL_CONTENT=NO
HISTORY_CONTENT_CLASS=COMMENT_ONLY_PLACEHOLDER
HEADER_EXISTS=NO
LIVE_CONSUMERS=0
CMAKE_PATTERN=BARE_APPEND_THEN_REMOVE   (append + later list(REMOVE_ITEM))
RENAME_GUARD_COMPLETED=YES
```

The shared 5-commit chain, content 1 line at every revision:

```text
93ef24fd0  A   rawrxd/src/deep2/<file>          created as 1-line stub
eb2dcf22b  D   rawrxd/src/deep2/<file>          deleted
d9f9b5866  A   rawrxd/src/deep2/<file>          re-added as 1-line stub
c5c22196b  R100  -> _n2_stage/src/deep2/<file>  1-line stub
7a73ec687  C100  -> rawrxd/src/deep2/<file>     1-line stub
```

`RENAME_GUARD_COMPLETED=YES` for all 19: renames and the copy from `_n2_stage` were both
inspected, and content is 1 line at every revision on every path. This is the guard working
as designed — it is the same mechanism that caught `deep2_end_to_end_bench.cpp`.

### 8.3 Non-code mentions, recorded so they are not re-litigated

None of these are consumers, but they are why a naive grep looks busy:

```text
src/core/unlinked_symbols_batch_022.cpp:344   COMMENT mentioning VAL038_Benchmark_Harness.cpp
docs/RAWRXD_MODEL_SUPPORT_SPEC_001.md:110      DOC mentioning GGUFLoader_Fixed.cpp / GGUFVerifier.cpp
scripts/completion_evaluator.py:108            STRING LITERALS "VAL038" / "VAL063", not paths
```

### 8.4 Outstanding — one gate remains before any retirement

```ini
SAME_BASENAME_OR_SYMBOL_TWIN=UNKNOWN
TWIN_PATH=UNKNOWN
TWIN_STATUS=UNKNOWN
```

The git chain proves the `_n2_stage` copies were 1-line **at those revisions**. It does not
establish what `_n2_stage` holds **now**. If any of the 19 has a richer live twin in
`_n2_stage`, the action is `REWIRE`, not `RETIRE`. Round 2 verifies current
`_n2_stage` line counts for all 19.

```ini
BUCKET_A_ELIGIBLE_NOW=0
ROUND_2_BLOCKS_ALL_RETIREMENTS=YES
FINAL_VERDICT=PENDING
```

## 9. Round 2 — twin search, and the first retirement

Method, auditable: repo-wide `Get-ChildItem -Recurse -Filter <basename>` from `F:\~dev`,
then content read and SHA256 comparison at every hit. Not a single known location — the
`_n2_stage` premise was checked, not assumed.

```ini
TWINS_WITH_REAL_CODE=0
CLEAN_STUBS_NO_RICH_TWIN=19
SEARCH_LOCATIONS_PER_FILE=6
SEARCH_SCANNED=ENTIRE F:\~dev TREE
ROUND2_TWIN_CHECK_RELIABLE=YES
```

Locations found, all byte-identical 1-line stubs:

```ini
F:\~dev\rawrxd\src\deep2\                                  <- live subject
F:\~dev\rawrxd copy\src\deep2\
F:\~dev\_n2_stage\src\deep2\                                 <- the R100 rename target
F:\~dev\.kilo\worktrees\festive-wakeboard\rawrxd\src\deep2\
F:\~dev\.kilo\worktrees\festive-wakeboard\rawrxd copy\src\deep2\
F:\~dev\.kilo\worktrees\festive-wakeboard\_\_n2_stage\src\deep2\
```

The git chain's claim that the `_n2_stage` copies were 1 line **at those revisions** is
confirmed to hold **on disk now**. That was the only open gate.

### 9.1 Ladder evaluation — 19 of 19

```ini
1. LIVE_CONSUMERS=0                   -> not ESCALATE
2. CURRENT_BODY_CLASS=PURE_STUB       -> not KEEP_OR_ESCALATE
3. RENAME_GUARD_COMPLETED=YES         -> not PENDING_UNRELIABLE
4. ROUND2_TWIN_CHECK_RELIABLE=YES     -> not PENDING_UNRELIABLE
5. HISTORY_CONFIDENCE=PROVEN_ABSENT   -> not PENDING_UNRELIABLE
6. LIVE_TWIN_RICHER=0                 -> not REWIRE
7. HISTORY_REAL_CONTENT=0             -> not RECOVER
8. INTENTIONAL_PLACEHOLDER=0          -> not KEEP
9. ACTION=RETIRE_ELIGIBLE
```

### 9.2 First retirement executed — `src/deep2/dump_tensors.cpp`

Done one at a time, as the mechanism proof, with the ladder evidence carried into both
the file and the CMake site.

```ini
FILE=src/deep2/dump_tensors.cpp
BODY -> comment-only retirement note, no code, declares nothing
CMAKE bare source entries 7249 (APPEND) and 7402 (REMOVE_ITEM) -> both removed
CMAKE_REFS_ARE_COMMENTS_ONLY=YES     verified: rg '^\s*src/deep2/dump_tensors\.cpp\s*$' -> 0
STUB_MARKER_COUNT=0
RESTORE=git -C F:/~dev checkout HEAD -- rawrxd/src/deep2/dump_tensors.cpp
```

Phantom membership was verified directly against the source before either edit, not taken
from either agent:

```ini
7249  src/deep2/dump_tensors.cpp   inside list(APPEND WIN32IDE_SOURCES ...)     opened 7103
7402  src/deep2/dump_tensors.cpp   inside list(REMOVE_ITEM WIN32IDE_SOURCES ...) opened 7391
```

### 9.3 Remaining 18 — authorized, deliberately deferred

```ini
AUTHORIZED_FOR_RETIRE=18
RETIRED_SO_FAR=1
DEFERRED=18
```

All 18 have cleared the ladder. They are **not** being retired in this tranche because the
mandated post-edit check cannot currently run: the tree does not link, for a reason
unrelated to this work.

```ini
POST_EDIT_EQUIVALENCE_REQUIRED=YES
POST_EDIT_EQUIVALENCE_POSSIBLE=NO
BLOCKER=Deep2::Wire::WireRecordDispatch LNK2019
BLOCKER_OWNER=lane that added untracked src/deep2/InferenceWire.cpp and wired
              Deep2Engine.cpp to call it without adding it to any target
BLOCKER_IS_MINE=NO
```

Batching 18 unverifiable build-graph edits into a tree that cannot compile is how the next
round of unmeasured changes happens. Step 6 of the action ordering is not optional; the
remaining 18 wait for it.

### 9.4 Method discrepancies recorded rather than reconciled silently

Three independent stub counts, three different numbers. None is authoritative until a single
canonical method exists:

```ini
TOTAL_STUBS   census agent  = 417   (src + tests)
              this agent     = 334   (src only)
              main session   = 426   (src + tests)
CAUSE         different scope and different line-count convention
CENSUS_DEFECT=APPEND_THEN_REMOVE reported as 0 -- REFUTED by direct source reading
MISSING_OUTPUT=HAS_HEADER=19 -- the list was never produced, and it is the highest-risk
               category in the population (a stub shipping a header may be declaring an
               API it never implements)
```

A census that undercounts is worse than one that fails loudly, because it converts a real
finding into silence. `APPEND_THEN_REMOVE=0` is exactly that, and it was caught only because
two agents disagreed and the tie was broken by reading the file.

Measurement artifact noted: round 2 reports `LIVE_LINES=2` where a direct read reports 1
line. `.Split("`n").Count` on content ending in a newline yields 2. Immaterial to any
decision, recorded because an unexplained 2x in a line count is the kind of thing that gets
quoted later without its context.

### 9.5 Second observation — a parallel worktree exists

```ini
WORKTREE_FOUND=F:\~dev\.kilo\worktrees\festive-wakeboard
STRAY_DUPLICATE_TREE=F:\~dev\rawrxd copy\
```

The worktree is a separate checkout, so file edits in this tree do not collide with it.
Shared resources — the git object store, any common build directory, and commits — remain
contended, which is the reason the equivalence A/B is serialized rather than run in parallel
with other lanes.

## 10. Source identity — pinned to a commit

This receipt was committed **mid-flight**, while its own `FINAL_VERDICT` was still `PENDING`.
That is recorded rather than tidied away, because a receipt that describes a source identity
must name it.

```ini
COMMIT=e7fb2efa0cc2d2fbfcb5e8d2585cd56452285253
COMMIT_SUBJECT=RAWRXD_DIRECT_IO_ARENA_AND_MANIFEST_001
COMMIT_AUTHOR=Garrett
COMMIT_DATE=2026-10-02T20:25:19-04:00

COMMIT_CONTAINS_THIS_RECEIPT=YES
COMMIT_CONTAINS_TRANCHE_1_RECEIPT=YES
COMMIT_CONTAINS_TRANCHE_1_AND_2_CMAKE_EDITS=YES
COMMIT_CONTAINS_BUILD_LOGS_AND_SCRATCH=YES
  audit_tombstone_001/*.log, validator_output.txt      (261-line build.log, 228-line configure.log)
  audit_gate_f66/only2.stderr.txt                     (1,689,898 bytes)
  kilo_tmp/compile_*.bat, configure_cert*.bat, link_cert.bat
```

Consequences recorded honestly:

```ini
TRANCHE_1_AND_2_CMAKE_EDITS_ARE_NOW_IN_HISTORY=YES
  # git diff for rawrxd/CMakeLists.txt shows ONLY the InferenceWire addition,
  # because HEAD already contains the tombstone retirements.
DUMP_TENSORS_RETIREMENT_STILL_UNCOMMITTED=YES
  # made after that commit, so it is the only tranche edit showing as modified
A_RECEIPT_COMMITTED_AS_PENDING=YES
  # correct and intended: the verdict was PENDING when the tree was committed,
  # and it remains PENDING now. It was not upgraded to satisfy a commit.
```

The commit also swept in build logs and scratch `.bat` files. That is history noise rather
than a correctness problem, and it is the author's call, but it means the repository now
carries 1.7 MB of stderr that will never be useful again. A `.gitignore` for
`audit_gate_f66/`, `kilo_tmp/`, and `*.stderr.txt` would prevent a recurrence.

### 10.1 Independent verification of `cmake/known_empty_sources.txt`

That file arrived in the same commit and implements a configure-time hard fail on any
empty-bodied source absent from the list. Checked directly, because a wrong list would
hard-fail a healthy tree:

```ini
ENTRIES=56
SPOT_CHECKED=8
ALL_SPOT_CHECKED_ENTRIES_GENUINELY_EMPTY_BODIED=YES
DEEP2_END_TO_END_BENCH_CPP_PRESENT_IN_LIST=NO   <- correct, it is 411 lines of real code
LIST_IS_ACCURATE=YES
```

One hypothesis of mine was refuted by the check and is recorded because refuting it is the
useful part: `src/vulkan_compute.cpp` looks like a false entry, since the arena lane cites
`BEGIN_CMD_ALLOC` in `vulkan_compute.cpp`. They are different files.

```ini
src\vulkan_compute.cpp          lines=2      noncomment=1      listed, correctly empty
src\deep2\vulkan_compute.cpp     lines=7255   noncomment=6240   holds BEGIN_CMD_ALLOC
```

The generator read the body, which is why the harness escaped without anyone exempting it.
That is the property this tranche argued for, arriving independently from another lane:

```ini
CHECK_THE_BODY_FIRST_THE_PATTERN_SECOND   # arrived via a different implementation
```

### 9.3 Batch retirement — 18 executed, post-edit verified

Deferred in the earlier revision pending a post-edit check that could actually run. It can
now run, so the deferral is discharged.

```ini
FILES_IN_BATCH=18   RETIRED=18   SKIPPED=0

PER_FILE_POSTCONDITIONS (asserted for every one of the 18, independently)
  bare_cmake_entries=0
  stub_marker_lines=0
  non_comment_lines=0
  cmake_paren_balance=0        (whole-file balance re-checked after each edit)
  files_with_leftover_entries=0   (re-swept across all 20 cohort files afterwards)

CMAKE_LINES_REMOVED=36          (18 append entries + 18 REMOVE_ITEM entries)
CMAKE_SHA_BEFORE =8BEF158A422EBDCA7CCD4249FF47B64EBD88CBB24EDB2F896061B418BB1860E3
CMAKE_SHA_AFTER  =C79E7A2A692815C187CACEBCB80BCF044559D6409DCACDC674D929E99B8A95CB
RESTORE_POINT=audit_tombstone_001/CMakeLists.PRE_BATCH.txt
```

### 9.4 Post-batch equivalence — the 36-line removal changed nothing

Measured, not argued. The link input set is the authority, not the binary hash:

```ini
PREBATCH_OBJ_COUNT=262     BATCH_OBJ_COUNT=262
PREBATCH_SRC_COUNT=271     BATCH_SRC_COUNT=271
OBJ diff = 0 / 0
SRC diff = 0 / 0
LINK_INPUT_SET_EQUAL_AFTER_36_LINE_REMOVAL=1
```

The raw ninja command text was **not** identical, and the difference was chased down rather
than waved through:

```ini
RAW_COMMAND_TEXT_IDENTICAL=False
differing lines=12   (6 pre-batch-only, 6 batch-only)
PAIRS_IDENTICAL_AFTER_TS_NORMALISATION=6 / 6
PAIRS_STILL_DIFFERING=0
```

Every one of the 12 differed solely in `-DRAWRXD_BUILD_TS`, a timestamp compiled into the
binary on every configure. After normalising that define, all six command pairs are
byte-identical.

This is the same principle the tombstone A/B established, arriving from a different angle
and independently confirming it: **this tree's binary is non-deterministic across configures
by design, so a hash comparison could never have been a valid equivalence authority here.**
Any future equivalence check that compares hashes will produce a confident and meaningless
answer.

### 9.5 Post-batch runtime — unchanged

```ini
CONFIGURE_EXIT=0   BUILD_EXIT=0   rawr-server.exe relinked and served
SERVER_EXE_SHA256=BAC8ECEBCB2FE7C0FCDFBFCC9FEFF23C89F8F0F60E77D8616F238D27907B7D1F
SERVER_IMAGE_MATCH=1
CHAT_MATCHES_BASELINE=YES    CHAT_USAGE=18/12/30
NEG 400 / 400 / 404 -> HEALTH_AFTER_NEGATIVES_MODEL_LOADED=True -> INFER_AFTER_ABUSE_OK=YES
NEG_DEAD_PORT_PROBE_VALID=1
SERVER_STILL_ALIVE=NO
```

The retirement changed the source list, the build graph, the binary bytes, and none of the
runtime behaviour. That is the expected result and it is now measured rather than assumed.

## 10. Defects found in this tranche's own instruments

Recorded because the instruments are the least trustworthy part of any audit.

```ini
PRECONDITION_NOT_ASSERTED_BEFORE_BATCH_EDIT
  The batch script asserts 5 preconditions per file, but its FIRST version had a parser
  error ("", as an array element) and therefore executed nothing. It happened to be safe
  by accident. A script that fails to parse leaves the tree untouched -- which is the
  only reason that revision did no damage.

FAILURE_MODE_WHERE_THE_GUARD_FIRED_BEFORE_THE_ACTION
  verify_batch_equivalence_001.ps1 checked for the existence of the file it was about to
  produce, before producing it. The guard fired immediately every time. Two further
  filename mismatches followed. Diagnosed by running `ninja -t commands rawr-server`
  directly -- 256 lines, works fine -- which localised the fault to the Start-Process
  cmd wrapper rather than to ninja. The comparison was then done directly instead of
  continuing to debug the wrapper.

OUTPUT_TRUNCATION_SILENTLY_DISABLED_HARNESS_TEARDOWN
  Piping the A/B harness through `Select-Object -First 60` terminated the pipeline
  mid-script, so its teardown never ran and the server leaked holding bin\rawr-server.exe.
  The next run then failed both builds with LNK1104 and still reported
  STRONGEST_NO_REBUILD, because ninja leaves the previous exe in place on a failed link.
  This is the most dangerous class encountered in this whole exercise: a harness that
  converts an operator's convenience into a false green. See tranche-1 receipt section 8.
```

## 11. Memorable

```ini
NOT_CURRENTLY_LINKED_IS_NOT_NEVER_MATTERED
A_REAL_PATH_THAT_CMAKE_MUST_SUBTRACT_IS_STALE_BUILD_INTENT_NOT_BOOKKEEPING_ERROR
GIT_LOG_FOLLOW_ALONE_CANNOT_PROVE_ABSENCE_ACROSS_RENAMES
RECOVERY_OUTRANKS_RETIREMENT_ALWAYS
NOT_CURRENTLY_LINKED
```

Full record: `rawrxd/audit/RAWRXD_PHANTOM_COHORT_TRIAGE_001/`