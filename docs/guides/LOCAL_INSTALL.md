# Local install (pointer)

**Authority:** repo-root [`INSTALL.md`](../../INSTALL.md)

**ASOF:** 2026-11-13 · **PROMOTE=0** · **CERTIFIED=0**

```
CLEAN_VM=ABSENT
NOT_PUBLISHED=1
```

Package managers remain **NOT_PUBLISHED** — see [`distribution/README.md`](../../distribution/README.md) and
`evidence/PRODUCTION_MATURITY_TOP25_001/TOP25_RECOGNITION_OPS_001/`.
Clean-VM install witness is **ABSENT** (do not invent). Tip-bound local build →
`rawr.exe` is the measured path only.

## Short path

```powershell
cmake -G Ninja -S . -B build_ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo
ninja -C build_ninja bin/rawr.exe
.\scripts\Verify-RawrLocalInstall.ps1
.\build_ninja\bin\rawr.exe --help
```

Fallback measured bins on some hosts: `build_clean\bin\rawr.exe`, `build-fd\bin\rawr.exe`
(Verify script accepts these if `build_ninja` is absent).

## Measured release zips (optional)

| Tag | Asset |
|-----|--------|
| `v14.7.3` | `RawrXD-14.7.3-Windows-x64.zip` |
| `v1.0.0` | `RawrXD-v1.0.0-Release.zip` |

Do not advertise MSI/DEB/DMG for those tags until the assets exist.
