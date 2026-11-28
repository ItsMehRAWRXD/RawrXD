# Primary product build — RawrXD-CLI-V2 + deep2_engine_lib (2026-11-28)

Full build of the primary CLI product under the modified CMake (build-integrity fail-closed
guards). This is the strongest build verification short of the GUI IDE.

## Command
```
cmake --build build\cmake-preset-ninja-release --target RawrXD-CLI-V2
  [76/79] Building CXX object .../rawr_cli.cpp.obj
  [77/79] Linking CXX static library Release\deep2_engine_lib.lib
  [78/79] Linking CXX executable bin-msvc\rawr.exe (+ RawrXD-ExtensionHost.exe)
  => BUILD_EXIT=0
```

## Result
- `deep2_engine_lib` (core engine, incl. the in-progress WIP sources) compiles + links cleanly
  (warnings only, no errors).
- `RawrXD-CLI-V2` compiles + links -> `bin-msvc\rawr.exe` (52,804,608 bytes).
- Binary runs: `rawr.exe --version` -> prints usage (unknown command handled), i.e. executes.

## Significance
- Confirms the Package 6 build-integrity CMake changes (RAWRXD_REQUIRE_PRODUCT_DEPS fail-closed)
  do NOT break the full product build.
- Confirms the Deep2 engine and the primary product are buildable at HEAD with the current WIP.
- `CERTIFIED=0` — this is BUILD verification, not runtime/certification. GPU acceptance and the
  GUI IDE remain separate (heavy/hardware).

## Functional smoke (real commands, freshly built exe)
```
rawr models        -> 11 loadable GGUF models listed (real inventory)        exit 0
rawr backend status-> backend router table (deep2/strata/ollama, health)     exit 2 (status)
rawr modes         -> 11 agent modes with permissions (code/ask/debug/...)   exit 0
```
The primary product is not merely built but FUNCTIONALLY OPERATIVE (real subcommands produce
real output). `[StreamEngine] Shutdown` is a clean shutdown message (stderr), not an error.

## State
IMPLEMENTED=1 CONFIGURED=1 BUILT=1 LINKED=1 RUNTIME_REACHED=1 FUNCTIONALLY_VERIFIED=1
COMMITTED=1 PUSHED=0