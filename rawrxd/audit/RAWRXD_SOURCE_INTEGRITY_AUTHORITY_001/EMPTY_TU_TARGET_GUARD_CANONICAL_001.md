# RAWRXD_EMPTY_TU_TARGET_GUARD_001 — canonical predicate, 6 call sites

Date: 2026-10-05
Type: systemic containment of the EXISTS-as-implementation defect family

```ini
DEFECT_INSTANCES_FOUND = 6   (DAP, SERVE, Crypto, address_resolver, pmc_profiler,
                               flame_graph_profiler)
CALL_SITES_NOW_GUARDED = 6
IMPLEMENTATIONS         = 1 function

CONFIGURE_EXIT (default)                     = 1   blocked on RawrXD-Crypto
CONFIGURE_EXIT (-DRAWRXD_ALLOW_EMPTY_TU_TARGETS=ON) = 0   build files written
CMAKE_ERROR_COUNT (acknowledge mode)          = 0
```

---

## 1. The bleeding was 4 targets, not 24

The text census reports declarations. The build graph reports targets. Crossing them:

```ini
leak declarations in CMake text          24
  of which create NO target at all       20   (cert/test fossils behind options,
                                              plus the 2 already fixed)
  of which create a REAL target           4   <- the live false greens
```

The 20 dead declarations cost nothing: no target, no binary, no receipt. They are
text noise, already visible in the census, and not bleeding.

## 2. All four name exactly one hollow source each

```text
RawrXD-Crypto            SHARED lib   src/security/uac_bypass_impl_stub.cpp
pmc_profiler             STATIC lib   src/profiling/pmc_profiler.cpp
flame_graph_profiler     STATIC lib   src/profiling/flame_graph.cpp
address_resolver_native  exe EXCLUDE_FROM_ALL  tools/address_resolver_native.cpp
```

Every one of those files is 459 bytes: a comment declaring it has no
implementation and exports no symbol.

**`RawrXD-Crypto` is the one that matters.** It is a SHARED library whose only C++
translation unit is a file named `uac_bypass_impl_stub.cpp` containing a comment.
Anyone linking that DLL receives a crypto library with no crypto in it, and the
link is green. Its own comment block already refers to
`RAWRXD_CRYPTO_DEF_LNK1104_001`, so this surface has a history.

The other three are profiling tools and an address resolver. A stub profiler has
no blast radius.

## 3. One predicate, six call sites

Six instances of one mistake is a missing abstraction, not six coincidences. Every
site had tested `EXISTS`, which cannot distinguish a restored stub from a restored
implementation. Extracted once:

```cmake
rawrxd_require_implemented_sources(<target> [STRICT|REPORT] <src>...)
```

Probes each source, detects `RAWRXD_GRAPH_RESTORED_001`, and refuses to let a
target be built from it. Severity is per call site:

```ini
STRICT   RawrXD-Crypto          fatal by default -- a silent correctness hazard
REPORT   the three tools        status-level, target still declared
```

Global fatality would have been the wrong call: failing an entire configure over a
profiler stub is blunt, and it only teaches people to pass the override flag.
Per-site severity keeps the security surface strict and the harmless surfaces loud.

### The gate refuses the shortcut explicitly

The failure message contains:

```text
Resolve deliberately -- do NOT silence this by appending to
cmake/known_empty_sources.txt, which would record the gap as accepted by
nobody. Choose one: implement it, retire it from the graph, or accept it
with a written reason.
```

Appending the four paths to the register would have moved
`RAWRXD_TARGETS_NAMING_LEAK_INLINE` from 4 to 0 and changed nothing. That is the
laundering move, and it is the one thing this guard is built to prevent.

### Both paths proven, not assumed

```ini
default                                    -> EXIT 1, fatal on RawrXD-Crypto
-DRAWRXD_ALLOW_EMPTY_TU_TARGETS=ON         -> EXIT 0, build files written,
                                             all 4 reported ACKNOWLEDGED, NOT DECIDED
```

## 4. DELIBERATE STATE CHANGE

**The tree no longer configures by default.** `RawrXD-Crypto` STRICT makes the
configure fail until one of the three remedies is chosen for
`src/security/uac_bypass_impl_stub.cpp`. That is the intended forcing function and
it is a one-line revert, but it is a real consequence and not a surprise:

```ini
to keep configuring while deciding:
  cmake -DRAWRXD_ALLOW_EMPTY_TU_TARGETS=ON ...
that flag is an ACKNOWLEDGEMENT, not a decision, and is reported as such
```

## 5. Defects I introduced this round

```ini
DEFECT_1  a PowerShell -replace injected a literal backtick-n into the
          RawrXD-Crypto call site instead of a newline, breaking the line.
          Caught by reading the call sites back after the rewrite.
DEFECT_2  I raised a false alarm that ~973 lines had been lost from
          CMakeLists.txt, by comparing the Read tool's line numbering (21234)
          against Measure-Object -Line (20261). Different counting methods.
          Measured properly against HEAD: 19595 -> 20261, i.e. +666.
          Exactly 4 deletions, all intentional guard replacements.
```

DEFECT_2 is worth recording because the reflex was to suspect I had damaged a
21k-line build file. The check that settled it was `git diff` filtered to deletions,
not a line count from memory.

## 6. State

```ini
EMPTY_TU_GUARD_FAMILY                   = CONTAINED   6/6 sites, 1 implementation
BLEEDING_LIVE_TARGETS                   = 4          all guarded, decision pending
DEAD_DECLARATIONS (no target)           = 20         text noise, no build cost
RAWXD_CRYPTO                            = STRICT     configure fails until decided
CLASS_GATE_LEAK                         = 74         unchanged by design
GUARD_AWARE_CENSUS                      = OPEN       leak count remains an UPPER BOUND
RAWRXD_TARGETS_NAMING_LEAK_INLINE       = 24         20 dead + 4 guarded
```