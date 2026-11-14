# RawrXD Quick Start — HISTORICAL / REDIRECT

**STATUS:** `HISTORICAL` · **ASOF:** 2026-11-13 · **PROMOTE=0** · **CERTIFIED=0** · **RELEASE=HELD**

> **Fail-closed:** Pre-built URL examples, `rawrxd --version`, `rawrxd model pull`,
> and package-manager snippets previously shown here are **NOT_PUBLISHED** /
> **NOT_RUN**. **Clean-VM install witness = ABSENT** (invent forbidden).
> Prefer repo-root [`INSTALL.md`](../INSTALL.md).

**Authority:** [`INSTALL.md`](../INSTALL.md) · [`guides/LOCAL_INSTALL.md`](guides/LOCAL_INSTALL.md)  
**Distribution:** [`distribution/README.md`](../distribution/README.md) (`NOT_PUBLISHED=1`)  
**Version drift:** `evidence/PRODUCTION_MATURITY_TOP25_001/VERSION_DRIFT.txt` (document-only)

## Measured first commands

```powershell
cmake -G Ninja -S . -B build_ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo
ninja -C build_ninja bin/rawr.exe
.\scripts\Verify-RawrLocalInstall.ps1
.\build_ninja\bin\rawr.exe --help
.\build_ninja\bin\rawr.exe paths
```

First inference: see [`INSTALL.md`](../INSTALL.md). Do not cite this file for
winget/choco/brew/MSI/DMG green paths.

## Legacy sections — HISTORICAL (do not follow)

Older QuickStart bodies (curl tarball, `rawrxd chat`, invented C++ Runtime API
snippets) are non-authoritative drafts. Git history retains them; product path
is local `rawr.exe` only under the recognition evidence pack.

*RawrXD QuickStart — HISTORICAL redirect · ASOF 2026-11-13 · PROMOTE=0*
