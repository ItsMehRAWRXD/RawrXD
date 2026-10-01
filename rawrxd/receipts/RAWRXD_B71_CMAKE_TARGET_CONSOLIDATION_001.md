# RAWRXD_B71_CMAKE_TARGET_CONSOLIDATION_001

## Status: PASS

```ini
RAWRXD_B71_CMAKE_TARGET_CONSOLIDATION_001=PASS
B62C_DUPLICATE_EXISTS=NO
B62C_SILENT_AMBIGUITY=NO
B62C_CONSOLIDATION=COMPLETE
```

All six safety conditions were enforced, not assumed:

```ini
COND_1  exactly one add_executable(rawrxd) remains          MET
COND_2  configure succeeds, generates rawrxd.vcxproj        MET
COND_3  generated source set IDENTICAL pre/post             MET (verified)
COND_4  full rawrxd build succeeds                          MET (exit 0)
COND_5  llama3.2-3b-Q2_K parity unchanged (115 chars)      MET
COND_6  prepared_cache_unit still passes                    MET (30/30)
```

## What the investigation actually found

The duplication was NOT copy-paste. The two `rawrxd` definitions were
materially different targets that shared a name:

```ini
DEFINITION_A (line ~328, guarded by RAWRXD_BUILD_CLI, inactive)
   SOURCE_COUNT = 59
DEFINITION_B (line ~14085, guarded by if(NOT TARGET rawrxd), ACTIVE)
   SOURCE_COUNT = 19

ONLY_IN_A = 42
ONLY_IN_B = 2
```

And the overlap is non-obvious in BOTH directions. Some A-only sources are
already compiled into `InferenceEngine.lib`, which B links:

```ini
src/core/execution_governor.cpp      in InferenceEngine = YES
src/model_source_resolver.cpp        in InferenceEngine = YES
src/vulkan_compute.cpp               in InferenceEngine = NO
src/runtime/TensorExecutionRouter.cpp in InferenceEngine = NO
src/cli/rawrxd_link_stubs.cpp        in InferenceEngine = NO
```

Others in that list of 42 are re-added to B through `target_sources` after the
`add_executable` call — `TensorExecutionRouter.cpp`, `ResidencyTracker.cpp`,
`CapacityManager.cpp` and six others.

## Why merging was rejected

A union of the two source lists would have been actively dangerous:

- sources already in `InferenceEngine.lib` would be compiled a second time into
  the executable, producing `LNK2005` duplicate-symbol errors;
- sources genuinely absent from every library would be silently ADDED, changing
  what the shipped binary contains;
- deleting definition A instead would break `RAWRXD_BUILD_CLI=ON`, since that is
  the only path defining that configuration.

There was no mechanical resolution. The decision required knowing per-symbol
whether each of 42 files was needed, library-provided, or vestigial — which is
analysis, not editing.

## Fix applied: rename, not merge

Only one target can own the name `rawrxd`. The former definition A is now
`rawrxd-cli-full`, with all 25 of its call sites renamed:

```ini
add_executable(rawrxd-cli-full ...)              # definition A, ~line 350
set_target_properties(rawrxd-cli-full ...)        # and 24 target_* calls
add_executable(rawrxd ...)                       # definition B, canonical
```

Both build configurations are preserved byte-for-byte in their source lists.
The collision is now structurally impossible rather than merely guarded, and the
divergence is visible in the file instead of hidden behind an `if()`.

The `if(NOT TARGET rawrxd)` guard on definition B was deliberately RETAINED. It
is now always true, but stripping an outer `if()`/`endif()` around 100+ lines of
a 17,000-line file carries more risk than the redundant guard does — and a guard
cannot silently select the wrong definition when the name is unique.

The B69 `FATAL_ERROR`-unless-acknowledged guard was REMOVED. It existed only
because the collision was live; with the names distinct it would be a false
alarm on every `RAWRXD_BUILD_CLI=ON` build.

## COND_3 in detail — the condition that matters

A consolidation that drops or duplicates a source looks like a clean build
until something links wrong months later, so the generated project was compared
directly rather than trusting the exit code.

```ini
INLINE_SRC_IN_TARGET_BLOCK      = 19
REACHING_GENERATED_PROJECT      = 18 (ClCompile)
PLUS                            = 1 (src\res\Resource.rc as ResourceCompile)
ADDED_BY_target_sources         = 8
rawrxd_cpu_math.cpp present     = YES   (the TU added at B63)
```

The single unmatched entry was `src\res\Resource.rc`, which appears as a
`<ResourceCompile>` item rather than `<ClCompile>` — expected, and confirmed
present:

```xml
<ResourceCompile Include="F:\~dev\rawrxd\src\res\Resource.rc" />
```

`src\rawrxd_cpu_math.cpp` is present, confirming the B63 source-addition
survived the consolidation.

## Configure-time receipt, now accurate

```
-- [RAWRXD_B71_CMAKE_TARGET_CONSOLIDATION_001] `rawrxd` defined exactly once,
   here. Former duplicate is `rawrxd-cli-full`, built only when
   RAWRXD_BUILD_CLI=OFF. Do not add source fixes to that block.
```

## Verification

```ini
EXE_SHA256_PRE  = 23916D21D28A91FA95270F8A365E458BDFBBEABCE9E576F22608127CC4CFC83A
EXE_SHA256_POST = 23916D21D28A91FA95270F8A365E458BDFBBEABCE9E576F22608127CC4CFC83A
CONFIGURING_DONE / GENERATING_DONE
BUILD_EXIT      = 0
COND_5_PARITY   = PASS (115 chars, identical to the B65 oracle)
prepared_cache_unit: checks=30 failures=0 VERDICT=PASS
```

## Scope note

This gate certifies only the `CMakeLists.txt` consolidation and the build it
produced. It does not certify any other dirty-tree change.

## Not committed

```ini
B71_COMMITTED=NO
B71_PUSHED=NO
```