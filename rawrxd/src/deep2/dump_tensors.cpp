// RAWRXD_PHANTOM_COHORT_TRIAGE_001
//
// RETIRED. Comment-only; declares nothing; referenced by NO CMake target.
//
// MEASURED BASIS (2026-10-03, two independent read-only passes, not assumed):
//
//   CURRENT_BODY_CLASS=PURE_STUB
//   LINE_COUNT=1                       (the single "// STUB:" line)
//   HEADER_EXISTS=0                    no dump_tensors.h / .hpp anywhere
//   LIVE_CONSUMERS=0                   no #include, no caller, no symbol reference
//   LIVE_REFERENCES=0                  in live source only; audit/, evidence/,
//                                      *.bak and root-level analysis dumps excluded
//
//   GIT HISTORY  5 revisions, 1 line of content at every one:
//     93ef24fd0  A   rawrxd/src/deep2/dump_tensors.cpp            created as stub
//     eb2dcf22b  D   rawrxd/src/deep2/dump_tensors.cpp            deleted
//     d9f9b5866  A   rawrxd/src/deep2/dump_tensors.cpp            re-added as stub
//     c5c22196b  R100 -> _n2_stage/src/deep2/dump_tensors.cpp     1 line
//     7a73ec687  C100 -> rawrxd/src/deep2/dump_tensors.cpp        1 line
//   HISTORY_CONFIDENCE=PROVEN_ABSENT
//
//   RENAME GUARD  the R100 rename and the C100 copy were both inspected, and
//                 content is 1 line at every revision on every path.
//
//   TWIN SEARCH  repo-wide `Get-ChildItem -Recurse -Filter dump_tensors.cpp`
//                found 6 locations, ALL byte-identical 1-line stubs:
//                  F:\~dev\rawrxd\src\deep2\
//                  F:\~dev\rawrxd copy\src\deep2\
//                  F:\~dev\_n2_stage\src\deep2\
//                  F:\~dev\.kilo\worktrees\festive-wakeboard\rawrxd\src\deep2\
//                  F:\~dev\.kilo\worktrees\festive-wakeboard\rawrxd copy\src\deep2\
//                  F:\~dev\.kilo\worktrees\festive-wakeboard\_\_n2_stage\src\deep2\
//                TWINS_WITH_REAL_CODE=0   ROUND2_TWIN_CHECK_RELIABLE=YES
//
//   CMAKE MEMBERSHIP  was a BARE PATH in list(APPEND WIN32IDE_SOURCES ...) and then
//                    stripped by list(REMOVE_ITEM WIN32IDE_SOURCES ...). It reached
//                    no target while the source list advertised it. Both entries are
//                    now removed and replaced by the measurement.
//
// Ladder outcome: ACTION=RETIRE_ELIGIBLE (all nine rungs cleared).
//
// SHA256_OF_STUB_AT_RETIREMENT=F8A1D62B...CB42 (recorded in the CMake note; full value in
// the audit receipt at rawrxd/audit/RAWRXD_PHANTOM_COHORT_TRIAGE_001/RECEIPT.md)
//
// NOTE ON THE ESCAPE THAT SHAPED THIS RULE
//
//   src/deep2/deep2_end_to_end_bench.cpp sits in the SAME CMake block as this file
//   and is 411 lines of REAL code with its own add_executable target. It entered the
//   same candidate cohort purely because it shares the append/remove pattern.
//   Had the body not been read first, the cheapest rule available -- "phantom
//   pattern means stub, so retire it" -- would have deleted a working harness
//   silently, with no build failure to reveal it.
//
//     CMAKE_PATTERN=PHANTOM  !=  CURRENT_BODY_CLASS=PURE_STUB
//     CHECK_THE_BODY_FIRST_THE_PATTERN_SECOND
//
// RESTORE = git -C F:/~dev checkout HEAD -- rawrxd/src/deep2/dump_tensors.cpp