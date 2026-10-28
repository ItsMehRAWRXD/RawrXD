# RECEIPT — WIN32IDE_BUILD_CLOSURE_001

```
PROMOTE=0
TIP_CLIMB=HOLD
CERTIFIED=0
PHASE=2
ASOF_UTC=2026-10-28T17:50:00Z
NO_INVENT_PASS=1
TIP_FREEZE_BIN_OVERWRITE=0
```

## Tip lock

| Field | Value |
|-------|-------|
| Path | `evidence/TIP_FREEZE_001/bin/RawrXD-Win32IDE.exe` |
| SHA256 | `748B210A8F17C6C47685BE1E2718CB0113C070E47881AD3A76B2EBB013934145` |
| Unchanged across Phase 2 | **YES** (verified; freeze `\bin` not written) |

## Disposition (fail-closed)

| Step | Result |
|------|--------|
| Incremental ninja RawrXD-Win32IDE (pre-edit) | **PASS** — `ninja: no work to do.` exit 0 |
| Candidate seal (pre tip-candidate rebuild) | `B4212E46598F6490241A531C88C8D9A8DA37532B8C940A2C38BB35226C5D869F` (= GhostText witness; **ABSORB=NOT_AUTHORIZED**) |
| Tip-candidate rebuild -j8 | **FAIL** — parallel `cl.exe` exit `-1`/`4294967295` (PDB contention; no Cxxxx) — `ninja_rebuild_minidump.log` |
| Tip-candidate rebuild -j2 | **FAIL** — `Win32IDE.cpp(6514)` **C2171** `operator '!'` on `void` (`SetCompletionBackendNative` decl/use race during GhostText SOURCE_WIRED wiring). Log excerpt in `ninja_rebuild_j2.log` |
| Post-fix state of decls | Forward decl + `unlinked_symbols_batch_021.cpp` now **`bool SetCompletionBackendNative`** — C2171 should clear on next clean compile; **NOT_REVERIFIED** this seal (machine saturated / rebuild incomplete) |
| Tip-candidate EXE post-rebuild | **NOT_PRODUCED** — link001 `\bin` still `B421…` |
| ninja log | Reset (`build log version is too old`); restat recompaction once `Permission denied` |

## Candidate SHA authority

```
CANDIDATE_SHA.txt = B421… (pre-rebuild copy only)
≠ TIP 748B210A…
≠ authorized GhostText product absorb
TIP_CANDIDATE_RELINK_COMPLETE=0
```

## Source delta this stream (non-sibling)

- `src/win32app/Win32IDE_CrashReporter.cpp` — `writeCrashMiniDump` on unhandled filter (A09 SOURCE_WIRED; tip RUNTIME NOT_RUN; not in tip binary; not in new candidate)

## Explicit non-claims

```
BUILD_TREE_INCREMENTAL_CLEAN=1
TIP_CANDIDATE_RELINK_COMPLETE=0
PROMOTE=0
A09_MET=0
GHOSTTEXT_ABSORB=NOT_AUTHORIZED
NOT_RUN != PASS
C2171_FIX_SOURCE_PRESENT != BUILD_VERIFIED
```
