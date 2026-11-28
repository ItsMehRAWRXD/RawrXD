# Build & configuration audit — 2026-11-28

Task: audit remaining items and configure the build to finish. Reconfigured with
`-DRAWRXD_BUILD_TESTS=ON` (89 tests registered) and built the full `all` target (369 targets).

## Product targets — GREEN
- `RawrXD-CLI-V2` (rawr.exe), `RawrXD-Win32IDE-Native.exe`, `deep2_engine_lib` — build clean.
- `rawrxd_production_hardening` + its 77-check test suite — build + pass.

## Pre-existing WIP build breaks found & FIXED (commit bf449a99ae)
1. `rawrxd_check.exe` — unresolved `mach_o_read`/`elf_read`:
   - top-level CMake target omitted `elf_reader.c` + `mach_o_reader.c` (subdir CMake had them);
   - `elf_reader.c` had wrong header offsets (read past the 48-byte header), wrong slot type
     (`elf_info_t*` vs `elf_segment_t*`), and a stray `#endif`;
   - `mach_o_reader.c` had a stray `#endif`.
   -> now builds green.
2. `rawrxd_loader_hardening_tests.exe` — unresolved `rawrxd::compression::compress/decompress`:
   added `src/codec/compression_core.cpp` to the target -> now builds green.

## Remaining pre-existing WIP breaks (NOT fixed — open-ended)
- `deep2_context_scaling.exe`, `deep2_d1_prefill_parity.exe` — unresolved
  `RawrXD::Deep2::RuntimeGraph::g_moe_expert_ms / g_moe_router_calls / g_moe_router_ms /
  g_moe_expert_calls`. These are declared as RuntimeGraph static members but defined as plain
  globals in `moe_timing.cpp` / `moe_timing_graph.cpp` (a declaration/definition mismatch).
  Fix: define the RuntimeGraph statics (or change the header to extern globals).
- The `all` build stops at these; additional auxiliary tool/test targets may have similar
  missing-source / WIP breaks further down the 369-target graph.

## Conclusion
The PRODUCT (CLI + GUI IDE + Deep2 engine + hardening) is fully configured and builds green.
The full `all` build is blocked only by pre-existing WIP breaks in AUXILIARY diagnostic/test
targets (2 fixed, ≥2 remaining). Greening all 369 targets is a WIP-repair effort, not a
configuration gap. `CERTIFIED=0` — build audit only.

## Next executable actions
1. Define `RuntimeGraph::g_moe_*` statics (or switch to extern globals) to unblock the deep2
   diagnostic tools.
2. Re-run the full build to surface any further auxiliary breaks.
3. Run `ctest` on the built tests for a pass/fail baseline.