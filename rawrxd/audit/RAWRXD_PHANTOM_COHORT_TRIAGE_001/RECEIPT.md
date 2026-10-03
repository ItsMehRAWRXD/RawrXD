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

## 9. Memorable

```ini
NOT_CURRENTLY_LINKED_IS_NOT_NEVER_MATTERED
A_REAL_PATH_THAT_CMAKE_MUST_SUBTRACT_IS_STALE_BUILD_INTENT_NOT_BOOKKEEPING_ERROR
GIT_LOG_FOLLOW_ALONE_CANNOT_PROVE_ABSENCE_ACROSS_RENAMES
RECOVERY_OUTRANKS_RETIREMENT_ALWAYS
NOT_CURRENTLY_LINKED
```

Full record: `rawrxd/audit/RAWRXD_PHANTOM_COHORT_TRIAGE_001/`