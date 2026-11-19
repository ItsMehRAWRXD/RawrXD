# P0 isolated native build

- Source revision before evidence commit: `475b86fc188a19bec56e2e62f22d4faa5f69828d`
- Configure: `cmake -S . -B build_sprint_20261119 -G "Visual Studio 17 2022" -DRAWRXD_BUILD_NATIVE_IDE=ON -DCMAKE_CONFIGURATION_TYPES=Release`
- Build: `cmake --build build_sprint_20261119 --target RawrXD-Win32IDE-Native --config Release --parallel 1`
- Result: fresh executable produced in the isolated build directory.
- Executable: `build_sprint_20261119/bin/Release/RawrXD-Win32IDE-Native.exe`
- Executable SHA-256: `970F80DFBC82744AC02AD7BCB8E1D10F5273257B8CDD93A9E47F35CCB2DF4AD2`
- Executable size: `2709504` bytes
- Build log: `build_sprint_20261119/rebuild.log`

This receipt records build evidence only. A real GUI Deep2 request against this fresh executable was not completed in this sprint; production GPU dispatch and response acceptance remain open.

```ini
ISOLATED_NATIVE_BUILD=PASS
FRESH_EXECUTABLE=PASS
GPU_IDE_RUNTIME=NOT_RUN
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```
