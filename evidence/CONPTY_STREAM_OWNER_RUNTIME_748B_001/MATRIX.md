# CONPTY_STREAM_OWNER_RUNTIME_748B_001 — matrix

```
PROMOTE=0 TIP_CLIMB=HOLD CERTIFIED=0
TIP_SHA=748B210A…934145
RELINK_CLOSED=1
RUNTIME_REACHED=0
RUNTIME_PASS=0
ABSORB_GHOSTTEXT=NOT_AUTHORIZED
```

| ID | Surface | Evidence | Disposition |
|----|---------|----------|-------------|
| R0 | Tip SHA freeze | `TIP_FREEZE_001` / `sha.txt` | **SHA_MATCH=1** |
| R1 | ConPTY string wire in tip | CreatePseudoConsole_* / CONPTY_STREAM_OWNER_001 | **RELINK_CLOSED** |
| R2 | Phase5 string wire in tip | SHELLLAYOUT_PHASE5_001 / null_hwnd / getPowerShellPanel | **RELINK_CLOSED** |
| R3 | GUI main HWND | RUNLOG MAIN_HWND≠0 | **REACHED** |
| R4 | Post 4001 PowerShell | PostMessage ok; NEW_PS=0 | **FAIL_CLOSED** |
| R5 | GateConPtyStream | GATE_STREAM absent | no stream fail file |
| R6 | GateTerminalMissing | GATE_TERMINAL absent | no chrome fail file |
| R7 | CHROME_VIS PHASE=5 | absent | **NOT invent PASS** |
| R8 | GhostText absorb | authority hold | **NOT_AUTHORIZED** |
| R9 | PROMOTE | law | **0** |
