# RAWRXD_GUARD_AWARE_EMPTY_TU_CENSUS_001

Date: 2026-10-05
Status: **PARTIAL — instrumentation runs, target resolution does not work in-configure**

```ini
CONFIGURE_EXIT = 0   CMAKE_ERROR_COUNT = 0
RAWRXD_GUARD_AWARE_EMPTY_TU_CENSUS_001 = NOT_ESTABLISHED
TEXTUAL_LEAK_DECLARATIONS = 24   (correct)
UNGUARDED_LIVE_FALSE_GREENS = UNKNOWN, not 0
```

---

## 1. What was built

`cmake/guard_aware_empty_tu_census.cmake`, included at the **end** of
`CMakeLists.txt` (line ~20305) because it needs configure-time state that does not
exist when the text census runs at the top of the file.

Two mechanisms, chosen so the census reads truth rather than re-guessing:

```cmake
# guards report on themselves, at the moment they fire
set_property(GLOBAL APPEND PROPERTY RAWRXD_GUARDED_EMPTY_TU
             "${target_name}|${_mode}|${_n_hollow}|${_hollow_text}")

# DAP and SERVE hand-written guards register into the same property
```

Registered guards: `rawrxd_require_implemented_sources` (4 sites),
`RawrXDScriptDAPAdapter`, `rawrxd-serve`. **6 total.**

Output: `audit/RAWRXD_GUARD_AWARE_EMPTY_TU_CENSUS_001/classification.tsv`

## 2. What does not work, and why

**Created-target state is not readable during configure on this generator.**
Measured, three attempts:

```ini
get_property(GLOBAL PROPERTY TARGETS)             -> 0
get_property(GLOBAL PROPERTY BUILDSYSTEM_TARGETS) -> 0
directory-scoped TARGETS                          -> not readable (get_property
                                                     scope/arity errors)
```

With an empty target list every declaration classifies as `NO_TARGET_CREATED`,
`UNGUARDED_LIVE_FALSE_GREENS` computes 0, and the census prints **PASS**.

**That PASS is vacuous and it was caught.** The first working run printed:

```text
TEXTUAL_LEAK_DECLARATIONS = TARGET;rawrxd-serve;RawrXD-Crypto;...   (a list, not a count)
NO_TARGET_CREATED         = 25
CONFIGURED_TARGETS_TOTAL  = 0
UNGUARDED_LIVE_FALSE_GREENS = 0
RAWRXD_GUARD_AWARE_EMPTY_TU_CENSUS_001 = PASS
```

A census that passes because it saw nothing is worse than no census. The PASS is
now gated on `_ga_targets_n GREATER 0` and the module reports
**NOT_ESTABLISHED** with the reason, stating that `NO_TARGET_CREATED=24` is an
artefact of seeing no targets and not a measurement.

## 3. Defects found in this instrument, in order

```ini
D1  PASS printed with 0 targets considered          -> vacuous PASS, now gated
D2  TEXTUAL_LEAK_DECLARATIONS printed the raw list  -> now a count; TSV header
                                                       row was also being counted
D3  GLOBAL PROPERTY BUILDSYSTEM_TARGETS read 0     -> real generator limitation
D4  get_property(_v TARGETS)      -> "incorrect number of arguments"
D5  get_property(_v PROPERTY T)   -> "invalid scope PROPERTY"
D6  A PowerShell -replace left an unbalanced message(STATUS( ... )
                                                    -> "Function missing ending )"
D7  Two edits with duplicate oldString text corrupted the registry write block:
      a spurious get_property(_recorded ...) inside rawrxd_filter_missing_sources,
      and the real one deleted from the end-of-configure block. Repaired by hand
      and re-verified; both blocks confirmed present.
```

D7 is the serious one and it was caught by grepping for the symbol rather than
assuming an edit landed. Two `if(RAWRXD_RECORD_EMPTY_SOURCES)` blocks exist in the
file legitimately; an edit intended for one matched the other.

## 4. The measurement that stands, and how it was obtained

Because the in-configure route is blocked, the live/dead split was measured
**externally**, which is a weaker claim and is labelled as such:

```ini
TEXTUAL_LEAK_DECLARATIONS = 24
  from   audit/RAWRXD_SOURCE_INTEGRITY_AUTHORITY_001/targets_naming_leak.tsv
NO_TARGET_CREATED         = 20
  from   cmake --build <dir> --target help   cross-referenced with the 24 names
LIVE_TARGETS              =  4
  RawrXD-Crypto, pmc_profiler, flame_graph_profiler, address_resolver_native
GUARDED_LIVE_TARGETS      =  4   all 4 guarded by rawrxd_require_implemented_sources
STRICT_GUARDED            =  1   RawrXD-Crypto
REPORT_GUARDED            =  3
UNGUARDED_LIVE_FALSE_GREENS=  0   by external cross-reference, NOT by this census
```

Caveat on the external route: `--target help` includes `EXCLUDE_FROM_ALL` targets,
which do exist and can be built on request, so counting them as live is correct.
It is still a post-configure observation, not configure-time proof.

## 5. To actually close this

Two options, neither built:

```ini
OPTION_A  record every created target into a global property at declaration time
          (a wrapper the build must call instead of bare add_executable)
          -> makes the census authoritative, at the cost of touching many sites

OPTION_B  run the census as a POST_BUILD step over the generated build system,
          where created targets are unambiguous
          -> no configure-time guessing; parses build.ninja / CMakeCache
```

Option B is smaller and cannot be fooled by property-scope semantics. It also runs
after generation, so `EXCLUDE_FROM_ALL` and default-build membership are both
directly observable rather than inferred.

## 6. Ledger

```ini
EMPTY_TU_GUARD_FAMILY        = CONTAINED   6/6 sites, 1 implementation
LIVE_FALSE_GREEN_TARGETS     = 4           all guarded (external cross-reference)
STRICT_FALSE_GREEN_TARGETS   = 1           RawrXD-Crypto, configure fails by default
REPORT_FALSE_GREEN_TARGETS   = 3
DEAD_DECLARATIONS            = 20          no target, no build cost
CLASS_GATE_LEAK              = 74          unchanged, upper-bound semantics
GUARD_AWARE_CENSUS           = PARTIAL     runs; target resolution unavailable
DEFAULT_CONFIGURE            = FAIL        intended, RawrXD-Crypto undecided
OVERRIDE_CONFIGURE           = PASS        acknowledged, not decided
```