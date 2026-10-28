# RECEIPT — NEURAL_CRDT_GATE_001

```
PROMOTE=0
TIP_CLIMB=HOLD
CERTIFIED=0
ABSORB=NOT_AUTHORIZED
NO_INVENT_PASS=1
WORKSPACE=G:\~dev\rawrxd
ASOF_UTC=2026-10-28T17:06:53Z
TIP_SHA=748B210A8F17C6C47685BE1E2718CB0113C070E47881AD3A76B2EBB013934145
RELINK=NO
```

## Verdict

Orphan `Win32NeuralBridge` C ABI fail-closed (`GateStub` + `0`). Product collab buffer
kept as **SOURCE_WIRED SYNTHETIC=partial** OT-lite (honest labels; not conflict-free
CRDT_PASS). Duplicate collab TUs remain **GATED_OMIT**. Tip EXE untouched.

## Dispositions

| Target | CMake / Win32IDE | Edit | Disposition |
|--------|------------------|------|-------------|
| Win32NeuralBridge.h | omit / orphan | cross-cite this LAW | GATED_STUB (prior) |
| Win32NeuralBridge.cpp | omit / orphan | Init/ops → GateStub + 0 | GATED_OMIT + GATED_STUB |
| crdt_buffer (include+src/collab) | linked | honest OT-lite labels | SOURCE_WIRED SYNTHETIC=partial |
| rawrxd_collab_crdt_impl / collab_cursor_impl | omit | GATED_OMIT banners | GATED_OMIT |
| src/collab/crdt_buffer.h RawrXD:: | orphan | sketch label | ORPHAN_SKETCH |

## Source touch

- `src/win32app/Win32NeuralBridge.cpp`
- `src/win32app/Win32NeuralBridge.h`
- `include/collab/crdt_buffer.h`
- `src/collab/crdt_buffer.cpp`
- `src/collab/crdt_buffer.h`
- `src/win32app/rawrxd_collab_crdt_impl.cpp`
- `src/win32app/collab_cursor_impl.cpp`
- `src/win32app/Win32IDE_Collab.cpp`
- `CMakeLists.txt` (omit cites only)

## EXE

| Field | Value |
|-------|-------|
| SHA256 | `748B210A8F17C6C47685BE1E2718CB0113C070E47881AD3A76B2EBB013934145` |
| Relink | NO |
| Absorb | NOT_AUTHORIZED |

## Held

- `PROMOTE=0` `TIP_CLIMB=HOLD` `CERTIFIED=0`
- Tip 748B preserved; no invent Collab/Neural RUNTIME PASS
- Camellia / GhostText absorb — not reopened

## Paths

- `evidence/NEURAL_CRDT_GATE_001/LAW.txt`
- `evidence/NEURAL_CRDT_GATE_001/MATRIX.md`
- `evidence/NEURAL_CRDT_GATE_001/RECEIPT.md`
