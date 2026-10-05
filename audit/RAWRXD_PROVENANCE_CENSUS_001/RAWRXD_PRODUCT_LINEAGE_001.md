# RAWRXD_PRODUCT_LINEAGE_001

Issued: 2026-10-05
Type: PRODUCT IDENTITY DECLARATION (not a certification, not a licence)
Authority basis: measurements in PROVENANCE_CENSUS_001 plus this file's own gates

```ini
## IDENTITY (pinned)

CANONICAL_PRODUCT_ANCESTOR   = dec16851343ea5519ea6ff918f9688d962956455
CANONICAL_CURRENT_HEAD      = bf93f1e81189632177d9a4c4d16e5759acba019a
CANONICAL_CURRENT_TREE      = 5654879c68242aada56eddb7b6821bfa4cd724d2

HISTORICAL_LINEAGE_HEAD     = 8dfeeaf0b729e2d76e0f23437bb52df3c256f0ad   (origin/main)
HISTORICAL_LINEAGE_TREE     = c237322ffb516b96d7d123e750a5d5aced8884db
HISTORICAL_LINEAGE_ROOTS    = e728a1b0cb 2022-09-18 Georgi Gerganov   (ggml upstream)
                               e6586ec5d2 2025-11-24 Garrett A Osborne
                               add63aa065 2025-12-07 RawrXD Developer

MERGE_BASE_DECLARED         = NONE  (verified empty)
DISJOINT_HISTORIES          = 1
SYMMETRIC_DIFF_COMMITS      = 3379

ORIGIN_MAIN_INCLUDED_IN_PRODUCT            = 0
ORIGIN_MAIN_INCLUDED_IN_SALE_SOURCE_PACKAGE = 0
ORIGIN_MAIN_ROLE                           = HISTORICAL_REFERENCE_ONLY
ORIGIN_MAIN_PRESERVED_FOR_FORENSICS         = 1

SOURCE_IDENTITY_DRIFT_DURING_AUDIT = 1
  HEAD advanced 7293ae44f -> bf93f1e81 during this audit
  ("test: add suite-authority runner and a declaration-matrix probe",
   ItsMehRAWRXD, 2026-10-04 22:50:14 -0400)
  All counts below were read against one of these two identities.
  Re-read before any figure is quoted externally.
```

## GATE 1 — AUTHORSHIP BY LINEAGE

```ini
CANONICAL_LINEAGE_AUTHOR_COUNT   = 2
  201  Garrett <garrett@example.com>
    7  ItsMehRAWRXD <noreply@github.com>
  THIRD_PARTY_AUTHORS_IN_PRODUCT = 0
  AGENT_OR_BOT_AUTHORS_IN_PRODUCT = 0

HISTORICAL_LINEAGE_AUTHOR_COUNT = 515
  dominated by inherited ggml upstream contributors:
    890 Georgi Gerganov <ggerganov@gmail.com>
    180 Jeff Bolz <jbolz@nvidia.com>
    170 Johannes Gaessler <johannesg@5d6.de>
    87 slaren / 79 Diego Devesa / 51 Daniel Bevenius / 42 Radoslav Gerganov ...
  THESE ARE INHERITED HISTORY, NOT RAWRXD CONTRIBUTORS

GIT_IDENTITY_TO_HOLDER_MAPPING = REQUIRED_BEFORE_LICENCE
  candidate single-holder set (all plausibly one person):
    garrett@example.com              NOTE: example.com is IANA-reserved, a placeholder
    garrettaosborne@gmail.com
    itsmehrawrxd@github.com
    noreply@github.com (account ItsMehRAWRXD)
  Real-world identity behind these four addresses is NOT established by this repo.
  DOCUMENTED_AS_UNVERIFIED = 1
```

## GATE 2 — CROSS-LINEAGE CONTENT TRANSFER

```ini
git diff --name-status -M canonical historical
  D   (in historical, absent from product)  10633
  A   (in product, absent from historical)    6115
  R100 (identical content, different path)    1840
  R09x (92-99% similar renames)                  62
  M   (same path, different content)              3

CROSS_LINEAGE_IDENTICAL_RENAMES = 1840
  Interpretation: directory reorganisation of the SAME working tree between two
  snapshots. Not third-party material crossing a provenance boundary.

PRODUCT_BLOBS_TOTAL                              = 9563
HISTORICAL_QUARANTINED_FILES (ggml/node_modules/
  Fixed_Reverse_Engineered/OrganizedPiProject/
  Spotify ADS Remover)                            = 1865
HISTORICAL_QUARANTINED_DISTINCT_BLOBS            = 1722
PRODUCT_BLOBS_MATCHING_QUARANTINED               = 183

  of which 178  = ZERO-BYTE blobs (git empty blob e69de29...) matching
                  3rdparty/ggml/.gitmodules. Build logs, stdout/stderr captures,
                  stamp files, tlog markers. CONTENT EMPTY. Not contamination.
  of which   4  = SUBSTANTIVE, all classified below.

CROSS_LINEAGE_UNKNOWN = 0
```

### The 4 substantive matches — ggml-derived build system

```ini
ORIGIN=DERIVED_FROM_GGML   LICENSE=MIT (ggml)   COMPLIANT=yes (notice retained on origin/main)

rawrxd/cmake/BuildTypes.cmake       == 3rdparty/ggml/cmake/BuildTypes.cmake        2037 B
rawrxd/cmake/GitVars.cmake         == 3rdparty/ggml/cmake/GitVars.cmake           717 B
rawrxd/cmake/common.cmake          == 3rdparty/ggml/cmake/common.cmake           2125 B
rawrxd/cmake/ggml-config.cmake.in  == 3rdparty/ggml/cmake/ggml-config.cmake.in   6914 B
```

**AMENDMENT to PROVENANCE_CENSUS_001 §4:** that section stated
`GGML_DERIVED_VERBATIM_CODE_IN_PRODUCT_SOURCE = 0`. Accurate for *product source*
(`rawrxd/src`, `rawrxd/tools`). **Not accurate for the build system:**
`rawrxd/cmake/` contains 4 byte-identical ggml files. ggml is MIT, so this is
compliant, but it belongs in the matrix and is now recorded.

Consequence: this project is a **ggml derivative in its build system**, which is
consistent with the retained ggml LICENSE on 48 branches. That licence is correct.

## GATE 3 — PRODUCT-LINEAGE PROVENANCE

```ini
UNKNOWN_SOURCE_COUNT                = 0
UNLICENSED_THIRD_PARTY_COUNT        = 0   nlohmann/json + quickjs, notices in-file
LICENSE_CONFLICT_COUNT              = 0
UNATTRIBUTED_DERIVED_COUNT          = 4   ggml cmake files, MIT, classified above
QUARANTINED_SOURCE_IN_PRODUCT_TREE  = 0
GGML_DERIVED_CODE_IN_PRODUCT_SOURCE = 0   src/ and tools/ only
GGML_DERIVED_CODE_IN_BUILD_SYSTEM   = 4   MIT, compliant
ZERO_DEPENDENCY_CLAIM               = FALSE  (vendored: nlohmann/json, quickjs)

VERDICT = PASS
  iff CROSS_LINEAGE_UNKNOWN == 0  -> satisfied
```

## HYGIENE — REPRICED AGAINST TRACKED STATE ONLY

The 12.50 GB / 17,204 artifact figure was a WORKING-DIRECTORY count. The split:

```ini
TRACKED_TOTAL_FILES        = 12547
TRACKED_ARTIFACT_FILES     = 232      2.06 MB
  173 .tlog   25 .lastbuildstate   21 .stamp   10 .exe   3 .obj
TRACKED_NON_ARTIFACT_FILES = 12315    1193.96 MB
UNTRACKED_ARTIFACTS        = ~16972    ~12.50 GB   (working dir only, NOT in the repo)

WORKING_DIRTY              = 366 files

HYGIENE_PROBLEM_IN_REPOSITORY      = SMALL   (232 files / 2.06 MB)
HYGIENE_PROBLEM_IN_WORKING_TREE    = LARGE   (12.50 GB, untracked)
DO_NOT_PRICE_HYGIENE_FROM_FS_COUNT = 1
```

Drop rule for the acquisition branch is therefore cheap in git terms:
`.tlog`, `.lastbuildstate`, `.stamp`, `.exe`, `.obj` plus the underscore-prefixed
scratch trees (`_n2_stage` 1420, `kilo_tmp` 1405, `_fleet_build` 125,
`_vp2_build` 106, `_deps` 75, `_ide_stub_closure_recovery_001` 154).

## WHAT THIS DECLARATION DOES NOT ESTABLISH

```ini
DOES_NOT_ESTABLISH = title or chain of title to the real-world author
DOES_NOT_ESTABLISH = any performance claim (8,259 TPS retracted; TTFT 2640-3239 ms)
DOES_NOT_ESTABLISH = GPU numerical correctness (GATE_1_CPU_GPU_NUMERICAL = FAIL)
DOES_NOT_ESTABLISH = a working DAP surface (459-byte comment-only TU)
DOES_NOT_ESTABLISH = benchmark evidence (harness real, zero result files)
DOES_NOT_ESTABLISH = that the 207/208-commit lineage is the LONGEST history
   (the historical lineage is 3172 commits and contains the project's earlier era)
```

## NEXT GATES

```ini
G4  real contributor identity behind the 4 git addresses   REQUIRED_BEFORE_LICENCE
G5  root LICENSE naming the verified holder, MIT chosen for  UNBLOCKED
    operational simplicity (92 files already declare SPDX MIT)
G6  acquisition-clean branch from bf93f1e81 + clean build   READY
G7  FORENSIC tags on both lineages, hashed, never rewritten READY
G8  close GATE_1, DAP TU, retract 8259/TTFT externally      UNCHANGED
```