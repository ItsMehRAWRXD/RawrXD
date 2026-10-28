# RECEIPT — IDE_BRIDGE_STUB_GATE_001

```
PROMOTE=0
TIP_CLIMB=HOLD
CERTIFIED=0
WORKSPACE=G:\~dev\rawrxd
ASOF_UTC=2026-10-28T08:35:00Z
```

## Verdict

Fake-success bridge stubs fail-closed. Neither target is in the RawrXD-Win32IDE
product link. Bodies now match GateMode: `OutputDebugString` + `false`;
smoke report string is `NOT_PASS`. Sealed EXE untouched (`RELINK=NO`).

## Dispositions

| Target | CMake / Win32IDE | Edit | Disposition |
|--------|------------------|------|-------------|
| ExtensionHostIpcBridge | omit from WIN32IDE_SOURCES; SmokeE2EIPC companion only | GateStub + Connect/Send/Receive/IsConnected → false | GATED_OMIT + GATED_STUB |
| Win32NeuralBridge.h | orphan (no includes; NeuralBridge.cpp omit) | Initialize/RunSmokeTest → false; report NOT_PASS | GATED_STUB |

## Source touch

- `src/win32app/ExtensionHostIpcBridge.cpp`
- `src/win32app/ExtensionHostIpcBridge.hpp`
- `src/win32app/Win32NeuralBridge.h`

## EXE

| Field | Value |
|-------|-------|
| SHA256 | `89BFD6142CEE7A6AA537DF0297014E240C7CC55B142C230521527914469F8630` |
| Relink | NO |
| Note | Relink would invalidate tetrad SHA |

## Held

- Camellia Auth / `RUNTIME_AUTH_E2E` — not reopened
- `PROMOTE=0` `TIP_CLIMB=HOLD` `CERTIFIED=0`

## Paths

- `evidence/IDE_BRIDGE_STUB_GATE_001/LAW.txt`
- `evidence/IDE_BRIDGE_STUB_GATE_001/MATRIX.md`
- `evidence/IDE_BRIDGE_STUB_GATE_001/RECEIPT.md`
