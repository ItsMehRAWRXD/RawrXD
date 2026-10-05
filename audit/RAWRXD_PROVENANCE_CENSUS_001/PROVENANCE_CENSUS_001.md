# RAWRXD_PROVENANCE_CENSUS_001

Date: 2026-10-05
Scope: authorship / provenance / license posture, F:\~dev and sibling repos on C:,D:,E:,F:,G:
Method: git object reads (authoritative), `rg` content probes, filesystem census.
Every number below is a measurement. Two of my own prior claims are RETRACTED here.

---

## 1. RETRACTIONS

```ini
RETRACTED_1=ROOT_LICENSE_NAMING_GGML_IS_MISATTRIBUTION
  was: "the repo asserts ggml's authors hold copyright over this codebase"
  now: FALSE. origin/main vendors ggml at 3rdparty/ggml/** (1,579 files) and carries
       genuine upstream ggml history (c82441c46 2023-08-29 "Merge pull request #485
       from rgerganov/add-mnist-cnn"). The root MIT naming "The ggml authors" is the
       MIT-required notice for a vendored dependency. It is compliance, not
       misattribution. rawrxd/ original source contains ZERO verbatim ggml code.

RETRACTED_2=LICENSE_ABSENT_ON_HEAD_IS_A_DEFECT_REQUIRING_AUTHORSHIP_AUDIT
  was: "fixable oversight; a licence defect; the single most legally pressing item"
  now: FALSE. HEAD vendors no ggml (0 files under any 3rdparty/ggml). Its vendored
       third-party material (nlohmann/json, quickjs) RETAINS its own in-file copyright
       notices, so MIT notice-retention is already satisfied where it is owed.
       A root licence on HEAD would declare intent for original code; it is not a
       defect repair and it is not gated on an authorship audit.
```

The prior "authorship audit then licence correction" recommendation, and the
+$1.5M-$3M attached to it, are withdrawn. They were built on RETRACTION_1.

---

## 2. REPOSITORY STRUCTURE: TWO DISJOINT REPOSITORIES

```ini
                          HEAD (beacon-residency-001)     origin/main
  commits                 207                              3172
  ancestry starts         2026-09-22                       2022-09-18 (ggml upstream)
  root commits            1                                3
  total tracked files     12546                            8030
  root LICENSE            ABSENT                           MIT "The ggml authors"
  vendored ggml           0                                1579 @ 3rdparty/ggml/**

  merge-base HEAD origin/main = EMPTY
  symmetric difference        = 3379 commits
  DISJOINT_HISTORIES          = 1        (no common ancestor)
```

### Root commits

```text
origin/main has THREE roots (unrelated histories merged):
  e728a1b0cb  2022-09-18  Georgi Gerganov       "Initial release"
  e6586ec5d2  2025-11-24  Garrett A Osborne      "Initial commit of RawrXD sources"
  add63aa065  2025-12-07  RawrXD Developer      "v1.1-lazy-telemetry: ..."

HEAD has ONE root:
  dec1685134  2026-09-22  Garrett <garrett@example.com>  2769 files
              subject: "cert: admission policy patch and e2e fixtures"
```

HEAD's root commit is a certification worker's commit, not a project genesis. The
published lineage and the working lineage have never been connected.

### Consequences

```ini
NOTHING_CERTIFIED_IS_PUBLISHED      all audit ledgers, GATE_1 measurement, corrected
                                    q4_0/q5_0 kernels and the 85-TPS roofline derivation
                                    live on the 207-commit orphan branch only
EVERYTHING_PUBLISHED_IS_UNCERTIFIED  origin/main carries the ~200-file benchmark harness,
                                    two node_modules trees, decompiled dumps and ~700
                                    root-level build artifacts; none of it is on HEAD
AUTHOR_IDENTITIES                   4 distinct: Georgi Gerganov / Garrett A Osborne /
                                    RawrXD Developer / Garrett <garrett@example.com>
WHICH_REPO_ARE_YOU_SELLING         differs by 4516 files net and 2965 commits
```

---

## 3. VENDORED THIRD-PARTY CENSUS

```ini
rawrxd/3rdparty/  46 tracked files, 2 libraries:
  nlohmann/   MIT   in-file: "Copyright (c) 2009 Florian Loitsch"
  quickjs/          in-file: "Copyright (c) 2017 Fabrice Bellard"
                            "Copyright (c) 2018 Charlie Gordon"
rawrxd/3rdparty/ggml/  ABSENT on HEAD

ZERO_DEPENDENCY_CLAIM = FALSE
  rawrxd/ vendored dependencies exist (nlohmann, quickjs)
NOTICE_RETENTION_SATISFIED_WHERE_OWED = 1  (both libs carry in-file notices)
```

---

## 4. GGML DERIVATION CENSUS — rawrxd/ original source

```ini
files including ggml.h / gguf.h / llama*.h      0
files carrying a ggml copyright notice          0
files referencing ggml_* symbols                4
    rawrxd/src/gguf_loader.hpp
    rawrxd/tools/q2k_dequant_probe.cpp
    rawrxd/src/core/rawrxd_demo.c
    rawrxd/src/core/SpeculativeEngine_GGUFBridge.hpp
files referencing llama_* symbols               3
    rawrxd/src/core/llama_decode_internal.{h,cpp}
    rawrxd/src/core/test_llama_decode.cpp
files referencing GGML_TYPE_* format ids        34

GGML_DERIVED_VERBATIM_CODE_IN_PRODUCT_SOURCE = 0
  The GGML_TYPE_* names are GGUF FILE-FORMAT identifiers (F32/Q4_0/Q4_K/Q5_K/Q6_K).
  They are a public container specification and are unavoidable in any GGUF reader.
  The 7 symbol-referencing files are original implementations, not copies.
```

---

## 5. SOURCE AND ARTIFACT CENSUS — rawrxd/

```ini
original source files (excl. build/, CMakeFiles, 3rdparty/)   4629      55.18 MB
original source lines                                               1355186
  non-blank estimate (78%)                                          1057 KLOC
build artifacts (.obj/.tlog/.exe/.pdb/.lib/.ilk)              17204      12.50 GB
SPDX-License-Identifier: MIT, 92 files, ZERO copyright-holder lines
explicit holder notices, 4 files:
    src/core/ArenaTelemetry.hpp
    src/deep2/QuantKernelRegistry.cpp
    src/core/pdb_gsi_hash.cpp
    src/core/SovereignTextBuffer.h
```

### LOC IS NOT A VALID DENOMINATOR FOR THIS ASSET

```ini
KLOC_ON_DISK                 = 1355
KLOC_ASSUMED_IN_VALUATION    = 100-150      (9-13x discrepancy)
REASON_LOC_OVERSTATES        = this repo has a DOCUMENTED pathology of stub files
                               counted as implementation:
  RAWRXD_DROPPED_SOURCE_TOTAL = 225 declared TUs never written
  minimal_dap_server.cpp      = 459-byte comment-only TU, exports no symbol
  marker-suffixed files visible in census:
    *.QUARANTINED  *.QUARANTINED_NOT_IN_CMAKE  *.DISCARDED_SIMULATED_NODES
    *.PRISTINE  *.REPAIRED  *.bak  *.bak2  *.old  *.tmp  *.disabled
COCOMO_KLOC_INPUT_IS_UNVALIDATED = 1
REPLACEMENT_COST_FROM_LOC      = NOT_COMPUTED   (input contradicts itself)
```

---

## 6. ACCEPTANCE GATES

```ini
UNKNOWN_SOURCE_COUNT                  = 0   in rawrxd/ original source
UNLICENSED_THIRD_PARTY_COUNT          = 0   nlohmann + quickjs both carry notices
LICENSE_CONFLICT_COUNT                = 0
UNATTRIBUTED_DERIVED_COUNT            = 0   no verbatim ggml/llama in product source
QUARANTINED_SOURCE_IN_PRODUCT_TREE     = 0

PROVENANCE_MATRIX_STATUS = COMPLETE_FOR_rawrxd
PROVENANCE_MATRIX_STATUS = INCOMPLETE_FOR_origin/main
  reason: origin/main additionally contains 3rdparty/ggml/** (1,579 files),
          two vendored node_modules trees, and decompiled third-party extracts
          (Fixed_Reverse_Engineered/, OrganizedPiProject/). Those require a
          SEPARATE provenance pass that this census did not perform.

LICENSE_CORRECTION_BLOCKED_ON_PROVENANCE_MATRIX = 0
  The blocker the correction was waiting on does not exist for rawrxd/.
  A root licence may now be written declaring intent for original code.
  If 3rdparty/ggml is ever re-vendored, ggml's notice must return with it.
```

---

## 7. RETIRED CLAIMS

```ini
CLAIM_8259_TPS               = RETRACTED_NO_PROVENANCE
  SEARCH_SCOPE               = all 5 drives, 10.24 TB, all 76 refs, full history
  MATCHES_IN_WORKING_TREE    = 0
  PICKAXE_HITS               = 30+ commits, ALL false positives: attention-score
                               logit text in checkpoint dumps
                               (MEAN=2594.88447, FIRST8=2580.96362,2575.95068,...)

CLAIM_SUB_10MS_TTFT          = REFUTED
  MEASURED_TTFT_1            = 2640 ms   _w6_integration_cert_receipt.md:44
  MEASURED_TTFT_2            = 3239 ms   _w10_output/GENERATION_QUALITY_001.txt:170
  OVERSTATEMENT              = 264x - 324x
  TTFT_MS=0.000000           = uninstrumented field, must never enter a results table

CLAIM_125_4_TPS              = UNSUPPORTED
  LOCATION                   = F:\rawrxd\benchmarks\sovereign_vs_ollama\README.md:181
  SELF_CONTRADICTION         = "Decode TPS: 125.4" (:181) vs "mean_tps": 89.4 (:357)
  BINARY                     = sovereign_vs_ollama_benchmark.exe DOES NOT EXIST
  RAW_RESULT_FILES           = 0 across the 200-file tree
  CORRECT_LABEL              = BENCHMARK_FRAMEWORK (harness real, results absent)
```

---

## 8. WHAT IS DEFENSIBLE

```ini
DEFENSIBLE
  85-TPS roofline derivation (README_85TPS_BATCH1.txt:10-18)
    1264 GB/s / 18.49 GB = 68.36 passes/s at impossible 100% efficiency
    54.69 passes/s at explicit 80% efficiency assumption
    85 / 54.69 = 1.554 verified tokens per weight pass REQUIRED
    PHYSICAL_BOUND=DERIVED  EFFICIENCY_ASSUMPTION=EXPLICIT  MEASURED_RESULT=NOT_IMPLIED
  DbgEng debugger engines   native_debugger_engine.cpp 88196 B, autonomous_debugger.cpp 34057 B
  Quant kernel correctness  q4_0/q5_0 nibble order FIXED and committed (e6ef0dfea)
  Audit/retraction trail    3 self-caught false-PASSes with commit hashes, in-repo
  Build graph defects       4 CMake defects found and fixed; 4 binaries link clean
  Original source corpus    4629 files / 55.18 MB, no verbatim third-party code

NOT DEFENSIBLE
  8,259 TPS                  no provenance in 10.24 TB
  sub-10ms TTFT              measured 2640-3239 ms
  certified GPU inference    GATE_1_CPU_GPU_NUMERICAL = FAIL, wrong top-1 token
  DAP / VS Code debug        459-byte comment-only TU, no exported symbol
  benchmark suite as evidence  harness real, zero results, self-contradicting README
  LOC-based replacement cost  1355 KLOC on disk vs 100-150 assumed; stubs inflate it
```