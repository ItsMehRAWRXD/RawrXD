# Authoritative no-Qt Native target + ModelLoader duplicate trees

```
PROMOTE=0
REBUILD_AUTHORITY=0
```

## Authoritative CMake target

- **Target:** `RawrXD-Win32IDE-Native`
- **Defined in:** `F:\rawrxd\CMakeLists.txt` (~L3837 `add_executable(RawrXD-Win32IDE-Native …)`)
- **Sources:** `src/win32app/*` (+ gguf/cpu helpers) — **not** `RawrXD-ModelLoader/src/win32app`
- **CI wire:** `.github/workflows/native-win32-nodeps-build.yml` builds `--target RawrXD-Win32IDE-Native` with `-DRAWRXD_REQUIRE_QT=OFF`

## Duplicate / parallel trees (note only; no consolidation this audit)

| Tree | Role |
|------|------|
| `src/win32app/` (53 files) | Authoritative Native IDE TU set |
| `RawrXD-ModelLoader/src/win32app/` (29 files) | Nested Qt-era/ModelLoader copy; Debugger.cpp SHA differs (`52103F60A6A0` vs `ED27F1A099FC`) |
| `RawrXD-ModelLoader/` (Qt6 hard-path in its CMakeLists) | Separate project; Qt-dependent |
| `src/model_loader/ModelLoader.{cpp,hpp}` | Product model-loader TU |
| `src/deep2/ModelLoader.hpp` + `UniversalModelLoader.hpp` | Deep2-side loader headers |

Gate 66 remains **Blocked** until one shipping graph is declared and the ModelLoader/Qt duplicate trees are excluded from authority claims.
