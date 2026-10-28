# NEURAL_CRDT_GATE_001 — matrix

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

| ID | Surface | Linked into Win32IDE? | Disposition | Cite |
|----|---------|----------------------|-------------|------|
| T01 | Win32NeuralBridge.h | NO | GATED_STUB false / NOT_PASS | IDE_BRIDGE + this LAW |
| T02 | Win32NeuralBridge.cpp C ABI | NO | GATED_OMIT + GATED_STUB return 0 | was Init→1 theater |
| T03 | Win32IDE_NeuralBridge.cpp | NO comment-omit | GATED_OMIT (prior) | CMakeLists ~7116 |
| T04a | include/collab/crdt_buffer.h | YES (include) | SOURCE_WIRED SYNTHETIC=partial | OT-lite; NOT CRDT_PASS |
| T04b | src/collab/crdt_buffer.cpp | YES | SOURCE_WIRED SYNTHETIC=partial | product owner |
| T04c | Win32IDE_Collab.cpp | YES | SOURCE_WIRED uses T04 | gate cite in header |
| T05a | rawrxd_collab_crdt_impl.cpp | NO | GATED_OMIT orphan dup | LNK2005 if linked |
| T05b | collab_cursor_impl.cpp | NO | GATED_OMIT orphan dup | LNK2005 if linked |
| T06 | src/collab/crdt_buffer.h RawrXD:: | NO | ORPHAN_SKETCH | ≠ product include |
| X01 | Tip absorb / GhostText | n/a | ABSORB=NOT_AUTHORIZED | GHOSTTEXT_SHA_AUTHORITY_HOLD_001 |

Preserve tip `748B210A…`. Source gate only. No invent PASS. No tip climb.
