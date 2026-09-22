# RawrXD local parity closure source drop

Dependency-free C++20 closure primitives for the last RawrXD IDE integration phase.

## Build the standalone contract selftest

Windows / MSVC:

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
.\build\Release\rawrxd_closure_selftest.exe
```

Expected tail:

```text
RAWRXD_LOCAL_PARITY_CLOSURE=PASS
```

This proves only the closure primitives. It does **not** certify the shipping RawrXD IDE.

Read `INTEGRATION_MAP.md` before copying anything into the main repository. The central rule is:
**reuse existing RawrXD source authority; only add a piece if the shipping path lacks that contract.**
