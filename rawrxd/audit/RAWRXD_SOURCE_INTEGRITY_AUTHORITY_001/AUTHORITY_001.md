# RAWRXD_SOURCE_INTEGRITY_AUTHORITY_001

Date: 2026-10-05
Type: CLASSIFICATION INSTRUMENT + TARGET-FILTER AUTHORITY
Answers: "are there 14 others like the DAP adapter?"
Answer: **37.**

```ini
CONFIGURE_EXIT                = 0
CMAKE_ERROR_COUNT             = 0
STRICT_MODE_EXIT             = 1     <- gate proven able to fail
RAWRXD_GRAPH_SOURCES_DECLARED_TOTAL = 1304
RAWRXD_GRAPH_SOURCES_ABSENT   = 0
RAWRXD_IMPLEMENTATION_DEFICIT_TOTAL = 301
RAWRXD_IMPLEMENTATION_DEFICIT_RATE  = 23%   (230 tenths)
CLASS_B_DECLARED_WITHHELD     = 227
CLASS_GATE_LEAK               = 74
TARGET_DECLARATIONS_PARSED    = 403
TARGETS_NAMING_ANY_HOLLOW     = 39
TARGETS_NAMING_LEAK           = 37
```

---

## 1. The two axes are different questions

```text
Does every declared source path exist?              YES   1304/1304
Does every declared source contain implementation?  NO     301/1304 hollow
```

`RAWRXD_GRAPH_SOURCES_ABSENT = 0` is not evidence that any product surface exists.
A tree can be 100% present, 23% hollow, link cleanly, and certify nothing. The
census reported both numbers all along; the second was not being read.

## 2. Classification — why "implement 301" would be wrong

The register (`cmake/known_empty_sources.txt`, 308 entries) makes the split
measurable instead of a matter of opinion. Its rule: an empty-bodied source
absent from it is a **hard configure error**. So:

```ini
CLASS_B_DECLARED_WITHHELD = 227  (75.4%)  hollow AND on the register
                                          a known gap, tolerated on purpose
CLASS_GATE_LEAK           =  74  (24.6%)  hollow, NOT on the register
                                          the gate never saw it -> a gate defect,
                                          NOT an accepted tolerance
CLASS_A / C / D / E       =  0    deferred; the B-vs-leak split must be
                                          resolved before finer classes mean
                                          anything. Assigning them now would be
                                          a guess wearing a classification.
```

Acting on all 301 would fill architectural fossils to move a counter. The
actionable population is the 74, and among those the 37 targets that reach them.

### Where the 74 are

```text
 15 src/sovereign        14 src/soloide       7 src/rkc        6 src/win32app
  6 src/serve             5 src/swarm          5 src/ide        5 src/test_harness
  2 src/profiling         1 src/agentic        1 src/script     1 src/core
  1 src/ui                1 src/llm_adapter    1 src/security   1 src/stubs.cpp
  1 src/model_config.cpp  1 tools/address_resolver_native.cpp
```

`src/sovereign` (15), `src/soloide` (14), `src/rkc` (7), `src/serve` (6),
`src/swarm` (5) read as whole subsystems from earlier project eras — the CLASS_D
(retire from graph) candidates, not implementation work.

## 3. Target-filter authority — the answer to "are there 14 others"

`rawrxd_filter_missing_sources()` is the canonical check. A target calling
`add_executable()` with a literal list never reaches it. This module parses all
**403** `add_executable` / `add_library` / `target_sources` declarations, strips
comments first (so a commented-out target is not counted), tracks parentheses to
balanced depth, and cross-references each inline project-owned source against the
hollow set and the register.

```ini
TARGETS_NAMING_ANY_HOLLOW_INLINE = 39
TARGETS_NAMING_LEAK_INLINE       = 37
```

Highest leak counts:

```text
rawrxd-serve                    6
SovereignTest_AutonomousAgent   5
SovereignTest_Suite             4
SovereignTest_HotPatcher        2
p1_ui_encoding_cert             1     (and 12 further cert targets at 1)
RawrXDScriptDAPAdapter          1
```

`rawrxd-serve` naming 6 leak sources is the one to look at first: a serving
surface assembled partly from comment-only units.

**`RawrXDScriptDAPAdapter` still appears in the list, and that is correct.** This
authority audits the CMake *text*, not the resolved target set. The declaration is
still present; the guard added under `RAWRXD_EMPTY_TU_TARGET_GUARD_001` is what
stops it producing a binary. A text audit reporting a declaration the guard has
already neutralised is accurate, not a regression.

## 4. Falsification

```ini
cmake -DRAWRXD_STRICT_SOURCE_INTEGRITY=ON ...   -> EXIT 1
  [source_integrity] 74 empty-bodied source(s) are reachable by a target that
  does not pass through rawrxd_filter_missing_sources(), so they escaped the
  declared-unimplemented gate:
    see audit/RAWRXD_SOURCE_INTEGRITY_AUTHORITY_001/gate_leak.tsv
```

The strict flag is off by default so instrumentation cannot block a working tree.
It is ON in the command above, and the configure fails. The gate can disagree.

The error text deliberately refuses the tempting shortcut: *"Do not silence this by
adding it to the register -- that records the gap as accepted without anyone
deciding to accept it."*

## 5. Defects I introduced and caught in this instrument

Recorded because the instrument is the deliverable and its own errors are part of
its evidence quality.

```ini
DEFECT_1  RAWRXD_IMPLEMENTATION_DEFICIT_RATE printed 231%
          integer math produced tenths of a percent under a percent label
          FIXED: percent and tenths reported as separate fields

DEFECT_2  denominator 1304 was HARDCODED
          a graph change would have made the rate silently wrong -- a rate that
          cannot go wrong is a rate that carries no information
          FIXED: declared total is COUNTED from the census TSV
          (first attempt broke configure: math(EXPR) cannot take a bare variable
           name, it needs ${} substitution. CONFIGURE_EXIT went 0 -> 1. That is the
           same defect class documented at CMakeLists.txt:480-484. Fixed, re-verified
           exit 0.)

DEFECT_3  RAWRXD_TARGETS_NAMING_HOLLOW_INLINE was labelling the LEAK population
          FIXED: split into ANY_HOLLOW (39) and LEAK (37)
```

Net effect of DEFECT_2's intermediate breakage: the instrument was briefly louder
than the thing it instruments. Worth stating rather than quietly re-running until
green.

## 6. Machine-readable outputs

```text
audit/RAWRXD_SOURCE_INTEGRITY_AUTHORITY_001/
  gate_leak.tsv              74 rows   PATH/AREA/CLASS/DISPOSITION_REQUIRED
  declared_withheld.tsv     227 rows   the tolerated population
  target_declarations.tsv   403 rows   TARGET/INLINE/HOLLOW/LEAK/PATHS
  targets_naming_leak.tsv    37 rows   the defect family
```

## 7. Ledger

```ini
SOURCE_PATH_COMPLETENESS              = PASS   1304/1304
SOURCE_IMPLEMENTATION_CENSUS          = OPEN   301 HOLLOW  (23%)
EMPTY_REGISTRY_INTEGRITY               = PASS   union-preserving, shrink-detecting
DAP_TARGET_INTEGRITY                   = PASS   guard proven both directions
TARGET_SOURCE_FILTER_AUTHORITY         = OPEN   37 targets bypass the predicate
PRODUCT_COMPLETENESS_FROM_BUILD_GREEN  = NOT_ESTABLISHED

COMPLETION_CRITERION (adopted)
  Every declared build surface is exactly one of:
    IMPLEMENTED | WITHHELD | INTENTIONALLY_EMPTY | RETIRED
  with UNKNOWN = 0.
  "301 -> 0" is NOT the criterion; it would reward filling fossils.
```