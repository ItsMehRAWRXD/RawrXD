# RECEIPT — WIN32IDE_BINARY_PROVENANCE_003

```
PROMOTE=0
TIP_CLIMB=HOLD
CERTIFIED=0
NO_REBUILD=1
NO_RELINK=1
NO_INVENT_PASS=1
WORKSPACE=G:\~dev\rawrxd
MOTD_ACK=1
ASOF_UTC=2026-10-28T10:22:00Z
TIP_SHA=6832F439100C71AE7923A7736F71784039B7F6A9DE53C895E56E9C7932A9F8B2
CITE=TIP_ABSORB_SWARM_002
```

## Verdict

| Gate | Result |
|------|--------|
| Tip EXE SHA on-disk | **MATCH** `6832F439…` |
| Link map present + hashed | **YES** |
| PDB present + hashed | **YES** |
| SWARM objs (Selector/HttpTags/SubAgent) | **YES** (SHA + map; HttpTags `appendLocalOllamaHttpTags` LINKED) |
| Prior absorb pile in map | **YES** (ToolActionStatus / Composer / handlers) |
| Ninja/CMake fingerprints | **YES** (cite SWARM_002 reconfig+relink) |
| A01 reproducible attribution | **MET** |
| Bit-identical rebuild from current tree | **NOT CLAIMED** |
| PROMOTE | **0** |

## Tip EXE

| Field | Value |
|-------|-------|
| Path | `G:\~dev\rawrxd\build_win32ide_link001\bin\RawrXD-Win32IDE.exe` |
| Size | 331649536 |
| SHA256 | `6832F439100C71AE7923A7736F71784039B7F6A9DE53C895E56E9C7932A9F8B2` |
| MTIME_UTC | 2026-10-28T10:09:59Z |
| Prior tip | `C4FC9AE9…` (`TIP_ABSORB_RELINK_001`) |

## Map / PDB

| Artifact | Size | SHA256 |
|----------|------|--------|
| `RawrXD-Win32IDE.map` | 331037987 | `7D2045D0…BA69626` |
| `RawrXD-Win32IDE.pdb` | 79073280 | `7EEC88C9…EA736CB3` |

## Key objs

| Obj | Size | SHA256 | Map hits |
|-----|------|--------|----------|
| SwarmModelSelector | 1070910 | `607C0E47…CB5B4873` | 560 |
| SwarmOllamaHttpTags | 263105 | `AFB51C73…E6BDFE0` | 95 |
| SubAgent | 4395487 | `C9C95D76…04637321` | 2164 |
| ToolActionStatus | 1461998 | `F034F7DC…388BD9` | 31 |
| AgenticComposerUX | 1729558 | `5653CA08…BB2CC6` | 259 |
| rawrengine_command_handlers | 2109275 | `8C29048D…63D57AC` | 913 |
| command_handlers_comprehensive | 408354 | `C2928C8F…994076` | 339 |

## Build / git

| Artifact | SHA256 / value |
|----------|----------------|
| `build.ninja` | `7788C68D…EF10058` |
| `CMakeCache.txt` | `3B1B1185…F37A6FB2` |
| `.ninja_log` | `F39AC12C…14522F1B` |
| `TargetDirectories.txt` | `4C1AB864…FB5B7955` |
| `GIT_HEAD` | `219b0e5694e565575728faf6c820d3f76cfb8006` |

## Historical / superseded

- `WIN32IDE_BINARY_PROVENANCE_002` → **HISTORICAL** (C4FC9AE9 FAIL_CLOSED)
- `WIN32IDE_BINARY_PROVENANCE_001` → historical (866E9D1B only)
- Sibling A01 agent `331f85bf` (C4FC9AE9 target) → **SUPERSEDED**

## Missing / non-claims

- `compile_commands.json` — MISSING
- `rules.ninja` — MISSING
- Full link-input CXX `.obj` hash inventory — not sealed (key absorb TUs only)
- `BIT_IDENTICAL_REBUILD_FROM_CURRENT_TREE=0`
- `PROMOTE=0` · `TIP_CLIMB=HOLD` · `CERTIFIED=0`

## Artifacts

- `evidence/WIN32IDE_BINARY_PROVENANCE_003/LAW.txt`
- `evidence/WIN32IDE_BINARY_PROVENANCE_003/RECEIPT.md`
- `evidence/WIN32IDE_BINARY_PROVENANCE_003/objs.txt`
- `evidence/WIN32IDE_BINARY_PROVENANCE_003/live_observe.txt`
- `evidence/WIN32IDE_BINARY_PROVENANCE_003/map_excerpt.txt`
- `evidence/WIN32IDE_BINARY_PROVENANCE_003/BUNDLE_SHA256.txt`
