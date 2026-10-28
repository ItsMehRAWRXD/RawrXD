# IDE_BRIDGE_STUB_GATE_001 — matrix

```
PROMOTE=0
TIP_CLIMB=HOLD
CERTIFIED=0
WORKSPACE=G:\~dev\rawrxd
ASOF_UTC=2026-10-28T08:35:00Z
EXE_SHA256=89BFD6142CEE7A6AA537DF0297014E240C7CC55B142C230521527914469F8630
RELINK=NO
```

| ID | Surface | Linked into Win32IDE? | Disposition | Cite |
|----|---------|----------------------|-------------|------|
| T01 | ExtensionHostIpcBridge.cpp/.hpp | NO | GATED_OMIT + GATED_STUB (false) | SmokeE2EIPC companion only |
| T01b | Connect/Send/Receive | companion-only | GATED_STUB GateStub+false | was CreateFile success theater |
| T02 | Win32NeuralBridge.h Initialize | NO (orphan header) | GATED_STUB return false | was return true |
| T02b | Win32NeuralBridge.h RunSmokeTest | NO | GATED_STUB false + NOT_PASS report | was stub string + true |
| T02c | Win32IDE_NeuralBridge.cpp | NO comment-omit | GATED_OMIT (prior) | CMakeLists ~7093 |
| T02d | Win32NeuralBridge.cpp (C ABI) | NO | GATED_OMIT | not in CMake |
| X01 | Camellia Auth | n/a | DO_NOT_REOPEN | RUNTIME_AUTH_E2E PASS |

Preserve sealed EXE `89BFD614…`. Source gate only; no invent PASS.
