// RAWRXD_PHANTOM_COHORT_TRIAGE_001
//
// RETIRED. Comment-only; declares nothing; referenced by NO CMake target.
//
// Measured basis (two independent read-only passes, 2026-10-03):
//   CURRENT_BODY_CLASS=PURE_STUB     LINE_COUNT=1     HEADER_EXISTS=0
//   LIVE_CONSUMERS=0                LIVE_REFERENCES=0 (live source only)
//   HISTORY_CONFIDENCE=PROVEN_ABSENT   5 revisions, 1 line at every one
//     93ef24fd0 A -> eb2dcf22b D -> d9f9b5866 A -> c5c22196b R100 to _n2_stage
//     -> 7a73ec687 C100 back to rawrxd.  RENAME_GUARD_COMPLETED=YES
//   ROUND2_TWIN_CHECK_RELIABLE=YES    TWINS_WITH_REAL_CODE=0
//     6 same-basename locations found repo-wide, all byte-identical stubs:
//       rawrxd/src/deep2, rawrxd copy/src/deep2, _n2_stage/src/deep2,
//       and three .kilo/worktrees/festive-wakeboard copies
//   LADDER_ACTION=RETIRE_ELIGIBLE (9/9 rungs cleared)
//
// CMAKE_MEMBERSHIP was BARE_APPEND_THEN_REMOVE: a real path in
// list(APPEND WIN32IDE_SOURCES ...) that list(REMOVE_ITEM WIN32IDE_SOURCES ...)
// stripped before any target consumed it. Both entries removed.
//
// Cohort escape that shaped the rule applied to all 19:
//   src/deep2/deep2_end_to_end_bench.cpp sits in the SAME CMake block and is 411
//   lines of REAL code with its own add_executable target. It entered this cohort
//   only because it shares the append/remove pattern.
//     CMAKE_PATTERN=PHANTOM  !=  CURRENT_BODY_CLASS=PURE_STUB
//     CHECK_THE_BODY_FIRST_THE_PATTERN_SECOND
//
// RESTORE = git -C F:/~dev checkout HEAD -- rawrxd/src/deep2/moe_microbench.cpp
