# RECEIPT — WIN32IDE_BINARY_PROVENANCE_001

```
PROMOTE=0
TIP_CLIMB=HOLD
CERTIFIED=0
NO_REBUILD=1
NO_INVENT_PASS=1
WORKSPACE=G:\~dev\rawrxd
MOTD_ACK=1
ASOF_UTC=2026-10-28T09:39:45Z
```

## Verdict

| Gate | Result |
|------|--------|
| Tip EXE SHA on-disk | **MATCH** `866E9D1B…` |
| Link map present + hashed | **YES** |
| Camellia / Auth / Watchdog objs | **YES** (sizes+SHA; cite absorb/auth seals) |
| Ninja/CMake fingerprints | **YES** (`build.ninja`, `CMakeCache`, `.ninja_log`, `TargetDirectories`) |
| CMakeLists mtime + git HEAD | **YES** (dirty; mtime after EXE) |
| A01 reproducible attribution | **MET** |
| Bit-identical rebuild from current tree | **NOT CLAIMED** |
| PROMOTE | **0** |

## Tip EXE

| Field | Value |
|-------|-------|
| Path | `G:\~dev\rawrxd\build_win32ide_link001\bin\RawrXD-Win32IDE.exe` |
| Size | 331634176 |
| SHA256 | `866E9D1B3B6E617B7C6001EA3BFC754002C0CE61F8880FF6294C95B86E6A601F` |
| MTIME_UTC | 2026-10-28T08:58:18Z |

## Key objs

| Obj | Size | SHA256 |
|-----|------|--------|
| `RawrXD_Camellia256.obj` | 32137 | `49CE60B7…AE4DDC24` |
| `RawrXD_Camellia256_Auth.obj` | 21749 | `74D03180…61E2FB2D` |
| `RawrXD_Watchdog.obj` | 13256 | `8A0244FD…2604804E6` |

## Map

| Field | Value |
|-------|-------|
| Path | `build_win32ide_link001\bin\RawrXD-Win32IDE.map` |
| Size | 330888726 |
| SHA256 | `4463301500FEDE934CF0A527444C21D81A4C1049BFB3D2E02630906B4180F186` |
| Excerpt | `map_excerpt.txt` |

## Build / git

| Artifact | SHA256 / value |
|----------|----------------|
| `build.ninja` | `82B2A365…0BF32D7F` |
| `CMakeCache.txt` | `3B1B1185…F37A6FB2` |
| `.ninja_log` | `33242709…37FB922` |
| `GIT_HEAD` | `219b0e5694e565575728faf6c820d3f76cfb8006` |
| `CMakeLists.txt` dirty | 1 (mtime after EXE) |

## Missing / non-claims

- `compile_commands.json` — MISSING
- `rules.ninja` — MISSING
- Full link-input CXX `.obj` hash inventory — not sealed (key ASM only)
- `BIT_IDENTICAL_REBUILD_FROM_CURRENT_TREE=0`

## Artifacts

- `evidence/WIN32IDE_BINARY_PROVENANCE_001/LAW.txt`
- `evidence/WIN32IDE_BINARY_PROVENANCE_001/RECEIPT.md`
- `evidence/WIN32IDE_BINARY_PROVENANCE_001/BUNDLE_SHA256.txt`
- `evidence/WIN32IDE_BINARY_PROVENANCE_001/objs.txt`
- `evidence/WIN32IDE_BINARY_PROVENANCE_001/map_excerpt.txt`
