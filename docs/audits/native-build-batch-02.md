# Native IDE audit — batch 02: build/dependency gates (15)

Evidence: inspected current branch CMakeLists.txt and selected legacy Qt headers. This is a source audit, not a Windows build receipt. No third-party source is introduced.

| # | Finding / release gate | State |
|---|---|---|
| 01 | Native executable target `RawrXD-Win32IDE-Native` exists | CMake definition observed; compilation unverified |
| 02 | Native target checks its source-file existence before creation | Observed; missing sources may suppress target |
| 03 | Qt6 package discovery still exists | Observed; disabled by dedicated no-deps CI configuration |
| 04 | `RAWRXD_REQUIRE_QT` defaults OFF | Observed; not proof Qt is absent from native linkage |
| 05 | Qt6 link references exist elsewhere in CMake | Observed; target-scoped dependency graph needs verification |
| 06 | Legacy `src/qtapp/MainWindow.h` includes QMainWindow | Observed; historical reference |
| 07 | Legacy terminal pool uses QProcess and QWidget | Observed; native process lifecycle parity pending |
| 08 | Legacy Ollama proxy uses QNetworkAccessManager | Observed; native stream/cancel parity pending |
| 09 | Legacy MASM editor uses QSyntaxHighlighter | Observed; native editing parity pending |
| 10 | Optional zlib FetchContent download path exists | Observed; disabled in no-deps CI configuration |
| 11 | Second optional zlib fetch switch exists | Observed; disabled in no-deps CI configuration |
| 12 | Vulkan is configurable via ENABLE_VULKAN | Observed; CPU-only build gate sets OFF |
| 13 | ASM_MASM is globally enabled | Observed; Windows MSVC x64 runner required |
| 14 | CMake enforces x64 under MSVC | Observed; CI uses -A x64 |
| 15 | Full IDE build success, GUI smoke, and Deep2 inference | NOT VERIFIED; must produce separate receipts |

## Build command under CI
```powershell
cmake -S . -B build-nodeps -G "Visual Studio 17 2022" -A x64 -DRAWRXD_REQUIRE_QT=OFF -DENABLE_VULKAN=OFF -DUSE_ZLIB_FETCHCONTENT=OFF -DFETCHCONTENT_ZLIB=OFF -DCMAKE_DISABLE_FIND_PACKAGE_Qt6=TRUE -DCMAKE_DISABLE_FIND_PACKAGE_ZLIB=TRUE -DFETCHCONTENT_FULLY_DISCONNECTED=ON -DFETCHCONTENT_UPDATES_DISCONNECTED=ON
cmake --build build-nodeps --config Release --target RawrXD-Win32IDE-Native --parallel 4
```

## Migration policy
Preserve legacy Qt files; do not delete or bulk-convert without checking equivalent native implementation. For each recovered feature require active native build integration, functional witness, error/cancellation paths, regression test, and clean build. Do not merge into dirty local worktrees or count an audit row as an implementation.
