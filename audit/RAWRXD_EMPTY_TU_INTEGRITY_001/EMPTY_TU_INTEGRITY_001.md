# RAWRXD_EMPTY_TU_INTEGRITY_001

Date: 2026-10-05
Type: TWO BUILD-GRAPH REPAIRS + one measurement that re-frames the deficit
Authorisation: "get in there and fix whats broken and stop the bleeding"

```ini
CONFIGURE_EXIT                     = 0
BUILD_FILES_WRITTEN                = 1
CMAKE_ERROR_COUNT                  = 0
FALSIFICATION_PROBE                = 3/3 PASS, exit 0
REGISTRY_ENTRY_LOSS                = 0
SOURCE_FILES_MODIFIED              = rawrxd/CMakeLists.txt
                                   = rawrxd/cmake/known_empty_sources.txt (header only)
```

---

## 1. FIX — DAP adapter no longer builds from an empty translation unit

### The defect

`rawrxd/CMakeLists.txt:16773` gated a target on file existence alone:

```cmake
if(RAWRXD_BUILD_DAP_ADAPTER AND EXISTS ".../src/script/debug/minimal_dap_server.cpp")
    add_executable(RawrXDScriptDAPAdapter src/script/debug/minimal_dap_server.cpp)
```

That file is 459 bytes whose entire body is a comment stating it contains no
implementation and exports no symbol (`RAWRXD_GRAPH_RESTORED_001`). `EXISTS` is
not an implementation test, so the configure produced a linked, zero-export
`RawrXDScriptDAPAdapter` and printed a green `[DAP] ... target enabled` line.
A reader of the build log saw a debug adapter where none exists.

### Root cause, one level deeper

The project already gates empty-bodied sources. `rawrxd_filter_missing_sources()`
loads `cmake/known_empty_sources.txt` and treats an empty-bodied source absent from
that register as a **hard configure error**. The DAP target called `add_executable`
**directly**, bypassing the filter entirely — so it escaped both the missing-path
drop and the empty-body gate. That is why 308 empty sources are registered and
this one was not among them.

### The repair

The guard uses the census module's own predicate, deliberately:

```cmake
file(READ "${_dap_src}" _dap_body)
if(_dap_body MATCHES "RAWRXD_GRAPH_RESTORED_001")
    -> WITHHELD, reason reported
else()
    -> target created
```

One definition of "this unit is empty", used both where emptiness is counted
(`cmake/source_graph_census.cmake:127`) and where it is acted on. The withheld
target is reported rather than silently skipped, so its absence is distinguishable
from a configure that never considered it.

### Measured

```ini
RawrXDScriptDAPAdapter references in generated build.ninja = 0
RawrXDScriptDAPAdapter executable on disk                   = absent

[DAP] RAWRXD_DAP_ADAPTER=WITHHELD
[DAP] RAWRXD_DAP_REASON=translation unit is a graph-restoration stub
[DAP] RAWRXD_DAP_REASON_DETAIL=contains RAWRXD_GRAPH_RESTORED_001;
[DAP]   declares no implementation and exports no symbol
[DAP] NO VS Code debug surface is produced by this configure
RAWRXD_DAP_ADAPTER=WITHHELD occurrences in log = 1     (was 2; deduped)
```

### Falsification — the guard can disagree

A guard that always refuses is indistinguishable from a correct one.
`dap_guard_falsify.cmake` runs the same predicate over three fixtures:

```ini
F1_REAL_IMPLEMENTATION_USABLE=1   <- a real implementation is ACCEPTED
F2_STUB_WITHHELD=1
F3_ABSENT_WITHHELD=1
CHECKS=3  FAILS=0  VERDICT=PASS  EXIT=0
```

F1 is the check that matters: the guard is not a blanket refusal.
(Known probe defect: the `reason=` diagnostic prints empty because the function
signature declares only the usability out-param. The usability decision — the thing
under test — is correct. Cosmetic only.)

---

## 2. FIX — regenerating the empty-source register can no longer destroy it

### How this was found

I ran the documented recovery command while investigating fix 1:

```cmake
cmake -DRAWRXD_RECORD_EMPTY_SOURCES=ON ...
```

`cmake/known_empty_sources.txt` says in its own header: *"Regenerate deliberately;
never hand-edit."* It truncated the register:

```ini
before  308 entries  SHA F0257236FF7DEE055A299E053D2681B41A983E3E9AE30E4A9FAF00CF705866BE
after    57 entries  SHA 6A361E2EFB9C11C00F3AD2C1E1E7E6D5147451634852F593C825402D51C4EB4A
        git diff --stat: 251 deletions
```

Restored byte-identical from git; count 308, SHA back to `F0257236…`, status CLEAN.

### Why that is not cosmetic

The register's rule is that an empty-bodied source **absent** from it is a hard
configure error (`CMakeLists.txt:700-709`, FATAL_ERROR). Truncating 308 -> 57
converts 251 declared gaps back into fatal ones, so the next configure visiting
those lists fails. The project's own documented workflow for its most important
integrity gate was a self-inflicted brick.

### Cause

`RAWRXD_RECORDED_EMPTY` is a GLOBAL property that starts empty on every configure
and collects only sources that passed through `rawrxd_filter_missing_sources`
*in that run*. The write at `CMakeLists.txt:20657` emitted it wholesale. A comment
at 685-691 documents a *previous* truncation bug (per-call writes) and was fixed;
the remaining defect is that the accumulator was never **seeded** from the existing
declaration.

### The repair

```cmake
list(APPEND _recorded ${RAWRXD_KNOWN_EMPTY_SOURCES})
list(REMOVE_DUPLICATES _recorded)
```

plus a `REGISTRY_UNION prior=/added=/total=` line and a WARNING if the register
ever shrinks. The declared set is a register of known gaps, so regenerating it can
only add.

### Measured, by repeating the operation that broke it

```ini
BEFORE FIX   308 -> 57    251 destroyed
AFTER FIX    308 -> 308
  [declared_unimplemented] wrote 308 declared-unimplemented source(s)
  [declared_unimplemented] REGISTRY_UNION prior=308 added=0 total=308

git diff --numstat: 3 insertions, 1 deletion
NON_HEADER_CHANGED_LINES = 0        <- header comment only; zero entry changes
```

`added=0` confirms idempotence: the 57 sources this run observed were already
registered.

---

## 3. THE MEASUREMENT THAT RE-FRAMES THE DEFICIT

The census the project already ships reports, on every configure:

```ini
RAWRXD_GRAPH_SOURCES_REFERENCED    = 1304
RAWRXD_GRAPH_SOURCES_PRESENT       = 1304
RAWRXD_GRAPH_SOURCES_ABSENT        =    0
RAWRXD_GRAPH_RESTORED_EMPTY_UNITS  =  301
```

```ini
SOURCE_DEFICIT_MISSING             =    0   (0.0%)   "perfect"
SOURCE_DEFICIT_HOLLOW              =  301   (23.1%)  <- the actual bleeding
```

The ledger's historical figure was `RAWRXD_DROPPED_SOURCE_TOTAL = 225`, a
*missing-source* count. That axis now reads zero. The remaining deficit is on the
other axis: **301 of 1,304 declared translation units exist and contain no
implementation.** A build graph in which every declared file is present and 23% of
them are hollow produces green links that certify nothing.

The instrument for this already exists and is already reporting. It was simply not
being read as the primary number.

---

## 4. STATUS

```ini
DAP_TARGET_FALSE_GREEN              = FIXED   (verified in generated build.ninja)
EMPTY_SOURCE_REGISTER_DESTRUCTIVE   = FIXED   (verified by repeating the operation)
REGISTRY_ENTRY_LOSS                 = 0
CONFIGURE                           = PASS   (exit 0, 0 CMake errors)

OPEN, NOT ADDRESSED BY THIS RECEIPT
  301 hollow translation units         the dominant remaining defect
  GATE_1_CPU_GPU_NUMERICAL             FAIL, GPU emits wrong top-1 token
  8259 TPS / sub-10ms TTFT             retracted; still circulating externally
  IDE DAP surface                      absent by measurement, not yet implemented
  src/win32app declared sources        target-level reachability unaudited
```