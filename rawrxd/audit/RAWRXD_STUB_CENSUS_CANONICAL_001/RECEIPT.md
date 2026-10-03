# RAWRXD_STUB_CENSUS_CANONICAL_001

```ini
FINAL_VERDICT=PASS_CENSUS_COMPLETE
TOTAL_STUBS=398
LOAD_BEARING_STUBS=0
CENSUS_CLAIM_18_LOAD_BEARING=REFUTED
WIN32IDE_BUILDS_AND_LINKS=YES
```

Source: `tools/stub_census_canonical_001.ps1`. Per-file list: `audit_tombstone_001/stub_census_canonical.csv`.

---

## 1. Why this exists

The stub population had four incompatible totals on record and one provably wrong structural
claim. Nothing downstream of a census that cannot agree with itself is worth relying on.

```text
TOTAL_STUBS   334   round-2 agent   (src only)
              417   census agent   (src + tests)
              424   header agent   (src + tests)
              426   main session   (src + tests)
              398   THIS RECEIPT   (canonical method, below)
```

And one claim that was refuted by direct source reading rather than by argument:

```ini
APPEND_THEN_REMOVE=0      asserted by the census
APPEND_THEN_REMOVE=REAL   measured: the phantom cohort sits in list(APPEND WIN32IDE_SOURCES)
                          at line 7232 and is stripped by list(REMOVE_ITEM WIN32IDE_SOURCES)
                          at line 7404, which the filter does not even reach (filter is at 7455)
```

## 2. Canonical method

Stated explicitly so the difference from the other totals is explainable rather than mysterious.

```ini
ROOTS      = rawrxd\src , rawrxd\tests
EXTENSIONS = .cpp , .h , .hpp
PREDICATE  = FIRST line matches ^\s*//\s*STUB:
EXCLUDED   = paths containing \build, \evidence\, \audit\, _n2_stage, \.kilo, or *.bak
TOTAL_FILES_SCANNED=3388
```

```ini
TOTAL_STUBS_CANONICAL=398
STUBS_SRC=315
STUBS_TESTS=83
```

```text
deep2 274 · inference 11 · engine 9 · ide 6 · core 4 · gpu 3 · guardrails 2 · remainder singletons
```

### 2.1 The header-count discrepancy, reconciled

Not a disagreement once the method is stated:

```ini
SAME_DIRECTORY_PAIRING=19      <- this receipt, and the earlier census's figure
WHOLE_REPO_BASENAME_MATCHING=21 <- the header agent's figure
```

Both are correct. Whole-repo basename matching picks up two extra cases that have no
same-directory header. Recorded rather than averaged.

### 2.2 The count itself was wrong twice before landing

The header agent reported 23, then 21, having initially counted `src/engine/sampler.cpp` and
`src/sampling/Sampler.cpp` — neither of which exists. A number that is wrong twice before it
is right is worth stating next to the number.

---

## 3. Load-bearing-ness, measured by artifact rather than by parsing

Static CMake parsing produced the wrong structural answer, so it is not used for this question.
The ground truth is an artifact: **if a translation unit is a member of a target that was
really built, its object file exists.**

Measured in two configurations, the second of which builds the largest target in the tree.

```ini
CONFIG A  build_rawr_ninja   BUILD_RAW_SERVER=ON, RAWR_ENABLE_VULKAN=ON, WIN32IDE=OFF
          EMPIRICALLY_COMPILED_STUBS=0

CONFIG B  build_ide_probe     + RAWRXD_BUILD_WIN32IDE=ON, IDE target fully built (669 ninja
                               edges, 388 IDE objects, exe linked)
          EMPIRICALLY_COMPILED_STUBS=0     of 398

LOAD_BEARING_STUBS=0
```

**The census claim of 18 load-bearing stubs is refuted.** Not one of the 398 produces an object
file in a configuration that compiles 388 of the IDE's own sources.

The reconciled conclusion:

```ini
RAWRXD_STUB_RECONCILIATION_001 said: "comment-only stubs, link-neutral, zero impact"
  CONCLUSION_REACH_build_impact = CORRECT, and now measured
  REASON_GIVEN                  = WRONG (they are bare source paths, not comments)
```

A true conclusion reached by a false route still has to be re-derived. That is why this receipt
exists rather than a citation of the old one.

---

## 4. Incidental finding: the Win32 IDE builds

The IDE does not configure by default, and the reason is worth recording because it looks like
a blocker and is not one.

```ini
cmake -DRAWRXD_BUILD_WIN32IDE=ON                          -> FATAL (exit 1)
  CMakeLists.txt:474  WIN32IDE_SOURCES: 25 EMPTY-BODIED source(s) are NOT on the
  declared-unimplemented list
```

`cmake/known_empty_sources.txt` holds 56 entries, generated under `RAWRXD_BUILD_WIN32IDE=OFF`.
Those 25 IDE sources were therefore never recorded. **The generator's coverage depends on the
configuration it was run in, and the file is presented as configuration-independent.** That is
a real defect in a generated artifact, independent of this tranche.

Using the gate's own documented bypass, with no file mutated:

```ini
cmake -DRAWRXD_BUILD_WIN32IDE=ON -DRAWRXD_STRICT_EMPTY_SOURCES=ON   -> exit 0
ninja RawrXD-Win32IDE                                                -> exit 0
  [668/669] Linking CXX executable bin\RawrXD-Win32IDE.exe

ARTIFACT=bin/RawrXD-Win32IDE.exe
SIZE=22,361,600 bytes
SHA256=93697D402607150D2C3F505823D9B8EA934EAE37CFE241BFFD31BEAB2D001D13
```

So the IDE compiles and links **despite** 25 declared-but-empty translation units. Nothing the
IDE needs is defined only in those files; they are placeholders for features never wired in,
not regressions of features that once worked.

```ini
BIGGEST_SCHEDULE_RISK="does the IDE actually build"
  MEASURED_ANSWER=YES at commit e7fb2efa0, with the gate bypassed
  CAVEAT=the default configure path still refuses, because the declaration file is
         incomplete for the IDE configuration
  NOT_CLAIMED=that the IDE is functionally complete, or that it runs
```

---

## 5. Standing recommendation

`known_empty_sources.txt` should be regenerated with the IDE configuration included, and the
generator should be made to refuse to write a declaration that is scoped to one configuration
while presenting as global. Until then, the file's completeness is a function of how it was
produced, and nothing in it says so.

```text
cmake -DRAWRXD_BUILD_WIN32IDE=ON -DRAWRXD_RECORD_EMPTY_SOURCES=ON ...
```

Deliberately NOT executed here: it mutates a generated artifact that another lane produced, and
recording 25 sources as permanently declared-unimplemented would be wrong for any of them that
is mid-implementation.

---

## 6. Memorable

```ini
MEASURE_LOAD_BEARINGNESS_BY_ARTIFACT_NOT_BY_PARSING_THE_BUILD_GRAPH
A_GENERATED_DECLARATION_IS_ONLY_AS_COMPLETE_AS_THE_CONFIGURATION_THAT_GENERATED_IT
A_TRUE_CONCLUSION_REACHED_BY_A_FALSE_ROUTE_STILL_HAS_TO_BE_RE_DERIVED
A_DOES_NOT_CONFIGURE_RESULT_IS_NOT_AN_A_DOES_NOT_BUILD_RESULT
