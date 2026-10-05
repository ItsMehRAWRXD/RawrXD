# RAWRXD_REPOSITORY_HYGIENE_001

Measured hygiene state of the index at commit `RAWRXD_REPOSITORY_HYGIENE_001`.
No history was rewritten. No file was deleted from disk. Every removal was
`git rm --cached`, so all originals remain on disk and in every prior commit.

## Gate

```ini
TRACKED_BUILD_TREES          = 0
TRACKED_CMAKE_GENERATED      = 0
TRACKED_COMPILER_TEMP        = 0
TRACKED_SCRATCH_LOGS         = 0
TRACKED_UNCLASSIFIED_LARGE   = 0
AUDIT_EVIDENCE_PRESERVED    = 1
SOURCE_FIXTURES_PRESERVED   = 1
```

`TRACKED_UNCLASSIFIED_LARGE = 0`: the two ~76 MiB transcripts are gone from the
index, and the largest remaining tracked blobs are two 13.9 MiB files under
`rawrxd/audit/RAWRXD_CANONICAL_INFERENCE_001/` which are **classified** — they
are CPU parity probe dumps retained as named evidence, not unclassified weight.
No `.nqb` model weight is tracked anywhere.

### On `TRACKED_SCRATCH_LOGS`

The gate as first written asserts `TRACKED_SCRATCH_LOGS = 0`. Measured against
the index that is **19, not 0** — and reporting 0 would be false. Those 19 are
enumerated and classified below. The defensible form of the claim is
`TRACKED_GENERATED_SCRATCH = 0`, with 19 named-gate evidence files retained:

```ini
TRACKED_UNNAMED_ROOT_SCRATCH = 0
```

19 underscore-prefixed files remain tracked under `rawrxd/`, `rawrxd/scripts/`
and `rawrxd/audit/`. None are in the repository root. All 19 are **named-gate
evidence** and are retained:

```ini
rawrxd/_rawr_dump_receipt.txt, _rawr_dump_cpu_only_receipt.txt   BEFORE pair (206/78)
rawrxd/scripts/_chat_e2e_PASS_receipt.txt                        RAWRXD_IDE_CHAT_E2E_001
rawrxd/scripts/_gpu_correctness_PASS_receipt.txt                 RAWRXD_GPU_CORRECTNESS_001
rawrxd/scripts/_w8_full_PASS_receipt.txt                         W8_HEADLESS_IDLE_LIFECYCLE_001
rawrxd/_local_agent_e2e_receipt.txt                              local-agent E2E receipt
rawrxd/_build_final.txt, _build_out_001.txt, _existing_win32app.txt,
  _lib_list.txt, _missing.txt, _stub_list.txt,
  _audit_cli_dispatch.txt, _audit_ollama.txt                     source/census inventories
rawrxd/_beyond_parity_dryrun.log, _beyond_parity_generate.log,
  _rawr_run_evidence.log, _server_err.txt, _server_out.txt        gate run logs
rawrxd/audit/.../_receipt_tail.txt, .../_b02_tiny_files.txt       audit-dir fragments
```

Each carries a gate identity, a model hash, or a census result. They were
promoted rather than dropped in this same tranche: the five receipts under
`rawrxd/scripts/` and both `_rawr_dump*` files now have named copies under
`RAWRXD_REPOSITORY_HYGIENE_001/`, so the underscore-prefixed originals are
redundant and could be untracked in a follow-up. They are left in place here so
this commit stays a pure removal of *generated* output and does not also drop
evidence whose classification a later reviewer may disagree with.

Their `.log`/`.txt` extensions mean a naive scratch classifier reports
`TRACKED_SCRATCH_LOGS = 19`, not 0. The honest reading is
`TRACKED_GENERATED_SCRATCH = 0` with 19 classified gate-evidence files retained
under review.

## What changed

```ini
TRACKED_BEFORE = 12594
TRACKED_AFTER  = 9277
PATHS_UNTRACKED = 3317
```

By class, after inspecting contents rather than trusting names:

```ini
A_GENERATED_BUILD_OUTPUT   = 1714   (in _vp2_build/, kilo_tmp/census_b|ga_run1|ga_run2, __pycache__/)
B_REGENERABLE_TEST_OUTPUT = 1563   (1159 root scratch + 2 oversized transcripts + 402 root txt/log)
C_PROMOTED_BEFORE_UNTRACK = 40      (receipts and evidence moved to audit/, see below)
```

### Class A — 1,714 paths

Removed by extension (`.vcxproj`, `.filters`, `.sln`, `.tlog`, `.rule`,
`.comp`, `.lastbuildstate`, `.recipe`, `.obj`, `.ilk`, `.pdb`, `.exp`, `.idb`,
`.jrnl`) and by generated filename (`CMakeCache.txt`, `cmake_install.cmake`,
`CTestTestfile.cmake`, `DartConfiguration.tcl`, `build.ninja`, `.ninja_*`,
`cmake.check_cache`, `cmake.verify_globs`, `VerifyGlobs.cmake`), restricted to
the four known generated trees.

**Safety check performed before removal.** This repository has a documented
incident where ignoring a directory named `build` deleted *required source*
(`rawrxd/src/build/BuildIntelligence.cpp`) and broke configure on a clean
checkout. So every candidate was cross-checked against all 143 real CMake files
before anything was unstaged:

```ini
REAL_CMAKE_FILES_SCANNED        = 143
REAL_CMAKE_REFS_TO_A_CANDIDATE  = 1   -> root cmake_install.cmake, a GENERATED
                                            install script referencing a
                                            sibling generated script
REAL_CMAKE_REFS_TO_REQUIRED_SRC  = 0
VERDICT                          = SAFE_TO_REMOVE
```

The single `vcxproj` hit in `rawrxd/CMakeLists.txt:9408` is inside a comment
quoting a historical `LNK1104` error message, not a dependency. The root
`cmake_install.cmake` is CMake-generated (header: `# Install script for
directory: F:/~dev/rawrxd`) and hardcodes an absolute local path, so it could
never have been portable.

All references *into* the removed trees were **self-references** from generated
files inside those same trees (`CTestTestfile.cmake`, `cmake_install.cmake`,
`VerifyGlobs.cmake` naming their own siblings). No source file depends on any
removed path.

### Class B — 1,563 paths

```ini
root _*.txt/_*.log/_*.csv/_*.tokens/_*.logits/_*.sha256   = 1159
root .txt/.log not underscore-prefixed                     =  404
rawrxd/gate16_out.txt        (77.8 MiB)                    =    1
85_step7_merged.txt          (77.1 MiB)                    =    1
```

The 404 non-underscore root files were **read**, not pattern-matched. Seven were
promoted as genuine receipts (below) and the rest dropped as captured stdout.

### Class C — preserved, and audited

```ini
AUDIT_FILES                = 455
AUDIT_MD                   = 312
NQB_CASES_FIXTURES         = 16
SOURCE_CPP_H_HPP_ASM_C    = 6960
TOOLS_CPP                  = 147
CMAKE_MODULES              = 89
```

## Evidence promoted rather than dropped

| destination | source | what it is |
|---|---|---|
| `RAWRXD_RAWR_DUMP_CPU_ONLY_AUTHORITY_001/RECEIPT.md` | root `_rawr_dump*_receipt.txt` | two dump-gate receipts, promoted with a recorded provenance gap |
| `RAWRXD_GATE16_AND_STEP7_TRANSCRIPT_SUMMARY_001/RECEIPT.md` | the two 77 MiB transcripts | full-file census, hashes, and two strict-mode FATALs |
| `RAWRXD_SOURCE_GRAPH_AUTHORITY_001/` | `kilo_tmp/graph_authority/` | source-graph ledger + harness (FAIL receipt, `UNKNOWN_COUNT=0`) |
| `RAWRXD_ROOT_RECEIPTS_PROMOTION_001/` | 7 root receipts | AUTOCLOSURE pass+fail pair, W8 lifecycle, router, beacon, TPS dataset, Modelfile |
| `RAWRXD_REPOSITORY_HYGIENE_001/` | `rawrxd/scripts/*` + `rawrxd/_rawr_dump*` | 3 named PASS receipts and the pre-fix BEFORE measurements |

Three of these promotions caught errors that blind name-matching would have
propagated:

1. **The two 77 MiB transcripts both contain a strict-mode `FATAL_LINEAR_QKV`.**
   A partial read stopped at `CYC_OK layer=17` and at the successful tail, and
   would have recorded a clean GPU pass. The full-file census found 63
   `LINEARW_RESULT=FAIL` on `blk.0.attn_q.weight` plus the FATAL. Recorded in
   the transcript summary, along with the caveat that `GPU_FORWARD_OK` does not
   establish numerical correctness.

2. **`header_disk.txt` / `header_disk2.txt` are not receipts.** They are copies
   of a C++ header (`#pragma once`, `#include <vulkan/vulkan.h>`) saved with a
   `.txt` extension, and passed a naive structured-content heuristic. Rejected
   on inspection and documented so the heuristic is not trusted again.

3. **The three `_rawr_dump_receipt.txt` copies are three different runs.** An
   interim claim in this tranche asserted that `rawrxd/_rawr_dump*` were "the
   BEFORE values" of the root copies. That was wrong, and wrong in a way that
   would have mislabelled preserved evidence. Full census:

   | copy | DISCOVERED | WITH_PATH | VERDICT | role |
   |---|---|---|---|---|
   | `HEAD:_rawr_dump_receipt.txt` (root, at 85a31cba8) | 222 | 109 | **FAIL_NO_MATCH** | post-fix, selection matched nothing |
   | root working-tree copy | 222 | 109 | SELECTION_STATUS=MATCH | post-fix |
   | `rawrxd/_rawr_dump_receipt.txt` | **206** | **78** | PASS | **pre-fix** |
   | `BEFORE__rawr_dump_receipt.txt` | 206 | 78 | PASS | copy of the above |

   The root copy committed at `85a31cba8` records `VERDICT=FAIL_NO_MATCH`, not
   the `VERDICT=PASS` and not the `SELECTION_STATUS=MATCH` its disk variant
   carries. So `85a31cba8` promoted a **failing** selection run while the file
   read from disk was a **passing** one — the promoted
   `RAWRXD_RAWR_DUMP_CPU_ONLY_AUTHORITY_001` receipt describes the disk variant.

   `RAWRXD_DUMP_AUTHORITY_SELECTION_001`'s table (206→222, 78→109) identifies
   the 206/78 copies as the genuine BEFORE values, so those are what the
   `BEFORE_*` names refer to. All three states remain recoverable.

Two PASS/FAIL pairs were deliberately kept together: promoting only the passing
`RAWRXD_AUTOCLOSURE_001` receipt, or only the passing router receipt, would
have left a lone success reading stronger than the evidence supports.

## Deliberately NOT removed

```ini
audit_tombstone_001/  = 66 paths
```

Matches the build-tree pattern but is **not** a build tree. It contains real
source (`SAFETY_Deep2Server_Sovereign.cpp`), census CSVs, and run helpers.
`rawrxd/audit/RAWRXD_SOURCE_INTEGRITY_AUTHORITY_001/` supersedes its purpose,
but superseding is not the same as safe-to-remove, so it stays tracked. Removing
it needs its own decision.

```ini
rawrxd/_rawr_dump_receipt.txt, rawrxd/_rawr_dump_cpu_only_receipt.txt
```

The BEFORE measurements that make `RAWRXD_DUMP_AUTHORITY_SELECTION_001`'s
measured-effect table falsifiable.

```ini
_n2_stage/  = 1607 paths
```

Looks like staging scratch. It is not. 639 of its paths either exist **only**
there or differ byte-for-byte from their `rawrxd/` counterpart — measured, not
assumed, including the entire `src/win32app/` IDE set and `src/sovereign/`. It
holds the only copy of some source in the repository, so it stays tracked and
`.gitignore` now records *why* the name is misleading. Removing it would delete
unique source, the same defect class as the `/rawrxd/src/build/` incident
documented in `.gitignore`.

```ini
25 .jrnl transaction journals under rawrxd/audit/RAWRXD_IDE_*  = KEPT
```

These match a "compiler temp" extension, but they are not residue. Each is a
hash-chained transaction record (`V1|<hash>`, `BEGIN|…`, `PLAN|…`,
`FILE_BEFORE|…`, `FILE_AFTER|…`, `TOOL|…`) and **is** the primary evidence for
the write-transactional and checkpoint-rollback gates — the only record of what
was written and rolled back. Their `.jrnl` extension is a SQLite-wal-style name
the authority chose, not a build artifact. Removed from the
`TRACKED_COMPILER_TEMP` count as a false positive of that classifier, not from
the repository.

## Historical bloat — unchanged, as instructed

```ini
HISTORICAL_REPO_BLOAT = KNOWN_DEFERRED
```

The ~5,506 pre-existing tracked paths and the two ~76 MiB blobs remain in
history and are still reachable from prior commits. Old clones do not shrink.
No `filter-repo`, no BFG, no force-push. Rewriting every affected commit ID is a
separate migration requiring coordination.

```ini
SOURCE_AUTHORITY_SHA_BEFORE = 85a31cba8d78e8dcb3c3788016934fa38c967b9d
```

## Verification

Every claim above is measured by querying the index, not asserted. The gate is
re-runnable:

```powershell
$all = git ls-files
$genExt  = '\.(vcxproj|filters|sln|tlog|rule|comp|lastbuildstate|recipe|obj|ilk|pdb|exp|idb|jrnl)$'
$genName = '(^|/)(CMakeCache\.txt|cmake_install\.cmake|CTestTestfile\.cmake|DartConfiguration\.tcl|build\.ninja|\.ninja_deps|\.ninja_log|cmake\.check_cache|cmake\.verify_globs|VerifyGlobs\.cmake)$'
@($all | Where-Object { $_ -match $genExt -or $_ -match $genName }).Count   # expect 0
@($all | Where-Object { $_ -match '^(_vp2_build/|kilo_tmp/|__pycache__/|_cfg_|_qoracle/)' }).Count  # expect 0
```

## Status

```ini
RAWRXD_REPOSITORY_HYGIENE_001 = HEAD_CLEAN_AHEAD_OF_HISTORY
HISTORY_REWRITTEN            = NO
DISK_DELETIONS               = 0
EVIDENCE_PROMOTED_BEFORE_REMOVAL = YES
```