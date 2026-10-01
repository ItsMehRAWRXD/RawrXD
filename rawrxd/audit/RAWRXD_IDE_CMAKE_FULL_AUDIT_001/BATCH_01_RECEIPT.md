# RAWRXD_IDE_CMAKE_FULL_AUDIT_001 — BATCH 01 RECEIPT

```
RAWRXD_IDE_CMAKE_FULL_AUDIT_001 = IN_PROGRESS
BATCH=01
ITEMS_VERIFIED=15
SOURCE_MUTATION=0
STAGING=0
COMMIT=0
PUSH=0
HEAD=a078e3b87be6b22ed1fa6fce6a20bfdd980e4441 (pinned, unchanged)
CONCURRENT_WRITER_ACTIVE=yes
LEASE=RAWRXD_STUB_RECONCILIATION_001 (PID 23572)
DEEP2_LIFECYCLE_REPAIR=HOLD
```

## Items

1. **116 missing-handler names enumerated.** Count: 116, unique: 116.
   Source: `src/core/ssot_missing_handlers_provider.cpp:64`
   static_assert verified at line 68.
   Saved to `BATCH_01_116_missing_handlers.txt`.

2. **Missing-handler provider reachability.** Gated by
   `RAWRXD_ENABLE_MISSING_HANDLER_STUBS` declared at
   `CMakeLists.txt:251` (default OFF). The provider is added at
   lines 6065, 7463 only when the option is ON. **UNREACHABLE_IN_SHIPPING_CONFIG.**

3. **EnforceNoStubs vacuous.** Filter list at lines 6226-6259 runs
   BEFORE `EnforceNoStubs(RawrXD-Win32IDE)` at line 6944. Both
   `EXCLUDE REGEX` and `REMOVE_ITEM` operate on the same
   `WIN32IDE_SOURCES` list before the policy function sees it.
   **Vacuous gate confirmed.**

4. **Orphan targets enumerated.** 14 `add_executable|add_library`
   declarations across 7 orphan CMakeLists.txt files. With the
   `${PROJECT_NAME}` placeholder at `win32ide_strict:21` included,
   the count is **15 targets reachable only through the orphaned
   trees**. RECEIPT.md reported "17" — likely counting
   `${PROJECT_NAME}` plus a static-parse expansion that included
   test/non-target add_* variants. **15 verified.**

5. **225 WIN32IDE_SOURCES missing-bound paths enumerated.** First
   25 sampled at `BATCH_01_missing_paths_sample.txt`. All 225 are
   subsystem names (HeadlessIDE, MainLoop, agentic_bridge,
   CommandSurface, VSCodeUI, Themes, Annotations, etc.).

6. **74-entry `RAWR_AGENTIC_SOURCES` list enumerated.** All 74
   paths inside the `set(RAWR_AGENTIC_SOURCES ...)` block at
   `cmake/RawrAgenticCli.fragment.cmake:11-87`. The 85 figure in
   RECEIPT.md likely counts `target_sources(rawr ...)` reuse and
   pre-list expansions. **74 verified.**

7. **`RAWRXD_PRODUCTION_STRIP_STUB_SOURCES` declared.** Default
   OFF at `CMakeLists.txt:249`. Has multiple FATAL_ERROR guard
   interactions with other options (lines 260, 2950, 2953, 2972,
   6220, 6267, 7454, 7489). Incompatible with: build-CLI,
   stress/replay sources, SSOT handler replacement, MASM
   fallbacks, `RAWRXD_EMERGENCY_STUB_LINK`, missing-handler-stubs,
   `RAWRXD_STRICT_AGENTIC_REALITY=OFF`, ASAN, non-Release
   build type, non-MSVC, non-Windows, non-MASM,
   `RAWR_SSOT_PROVIDER != AUTO`, lack of MultiWindow_Kernel,
   lack of DynamicPromptEngine, no Python3, no
   `RAWRXD_ENABLE_HEAVY_GATES`.

8. **`RAWRXD_ALLOW_AGENTIC_STUB_FALLBACK` declared.** Default
   OFF at `CMakeLists.txt:6210`. Incompatible with strict
   production profile (line 6220) and with
   `_WIN32IDE_USE_MONOLITHIC_OBJS` (line 7216).

9. **`RAWRXD_STRICT_AGENTIC_REALITY` declared.** Default ON at
   `CMakeLists.txt:6263`. **Verified that the option is itself
   truthy in shipping**, and that
   `if(RAWRXD_STRICT_AGENTIC_REALITY AND NOT
   RAWRXD_ALLOW_AGENTIC_STUB_FALLBACK)` (lines 6270, 6419)
   gates strict-mode enforcement.

10. **`include(RawrXDStrictShipping)` — NEVER CALLED.** No
    occurrences of the include path in root `CMakeLists.txt`. The
    `rawrxd_enforce_shipping_target` ghost-source / stub-name /
    single-WinMain gate (defined in
    `cmake/RawrXDStrictShipping.cmake:40-75`) is therefore
    **UNREACHABLE_IN_SHIPPING_CONFIG**. Verified by grep.

11. **`include(RawrXDStrictWin32IDESourceClosure)` — NEVER
    CALLED.** No occurrences. The module is
    **UNREACHABLE_IN_SHIPPING_CONFIG**. Verified by grep.

12. **`ENV{RAWRXD_EMERGENCY_STUB_LINK}` — sole env read.**
    Referenced at `CMakeLists.txt:2973` (FATAL_ERROR when
    `RAWRXD_PRODUCTION_STRIP_STUB_SOURCES=ON` and env is
    defined) and line 6326 (the downgrade gate that turns the
    stub FATAL_ERROR at line 6329 into WARNING at line 6346).
    No other env reads in the build.

13. **`include(cmake/P1_ProductRuntimeAuthority.cmake)` is
    present** at `CMakeLists.txt:3`. **Verified.** This file is
    the only "P1" module that the root CMakeLists.txt
    actually includes. The RECEIPT.md table entry
    `cmake/P1_ProductRuntimeAuthority.cmake:4-6` for
    `RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY` is therefore live.

14. **`include(cmake/RawrXDBuildOptions.cmake)` — NEVER
    CALLED.** No occurrences in root CMakeLists.txt. The
    options `RAWRXD_ENABLE_MASM/AVX512/AMX/VULKAN/CUDA/ROCM/
    OPENCL/METAL/FLASH_ATTENTION/SPECULATIVE/STREAMING/BATCHING/
    DISTRIBUTED/ENCRYPTION/SANDBOX/AUDIT`,
    `RAWRXD_BUILD_TESTS/BENCHMARKS/EXAMPLES/DOCS`,
    `RAWRXD_ENABLE_PROFILING/SANITIZERS/COVERAGE` (defined at
    `cmake/RawrXDBuildOptions.cmake:16-44`) are **declared in
    a file that is never included**, so they never reach the
    CMake cache.

15. **`add_subdirectory()` calls classified.** 9 total:
    - **5 reach valid subtrees**: `src/reverse_engineering` (3366),
      `src/ceo` (3371), `src/repository` (3376),
      `src/generation` (3377), `rguf_source` (3382)
    - **4 are dead**: `src/runtime` (14031), `tests` (14036),
      `src/tools` (14197), `src/validation` (14202)
    - The four dead ones are guarded by
      `if(EXISTS .../CMakeLists.txt)` whose target file is
      absent on disk.
    - `rguf_source` looks like a typo for `gguf_source` but
      the directory does exist with a CMakeLists.txt on disk,
      so the call succeeds.

## Method

All items verified by read-only inspection of:
- `src/core/ssot_missing_handlers_provider.cpp`
- `cmake/RawrAgenticCli.fragment.cmake`
- `CMakeLists.txt` (root, 16,501 lines)
- `win32ide_strict/CMakeLists.txt`, `src/core/CMakeLists.txt`,
  `src/core/{executor,policy,router,scheduler}/CMakeLists.txt`,
  `src/runtime/os/CMakeLists.txt`

Zero source mutation. Zero staging. Zero commit. Zero push.
HEAD pinned at `a078e3b87`. Concurrent writer still active.

## Outstanding — no lease, no mutation

D2/D1/D3 lifecycle items remain `[ ]` until a fresh
`RAWRXD_DEEP2_GENERATION_LIFECYCLE_001` lease is granted.
Items in section H (25 beyond-parity subsystems) remain `[ ]`
because no audit evidence certifies any of them yet.
Items in section I (final completion gate) remain `[ ]` —
discovery is not fix.
