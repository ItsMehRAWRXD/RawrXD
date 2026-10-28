# RECEIPT — SWARM_PATH_B_4111_SOURCE_001

```
ASOF_UTC=2026-10-28T17:45:00Z
WORKSPACE=G:\~dev\rawrxd
WORKSTREAM=G07_PATH_B_SWARM_RUNTIME
GATE=SWARM_PATH_B_4111_SOURCE_001
DISPOSITION=SOURCE_WIRED
RELINK_REQUIRED=1
PROMOTE=0
```

## Mission

SOURCE_WIRE only for PathB IDM 4111 CmdDiag miss. Prior tip 748B delivered
WM_COMMAND 4111 but CmdDiag never saw id=4111. Fix source so 4111 reaches
CmdDiag → onSubAgentSwarm. Do not overwrite `TIP_FREEZE_001\bin`. Land in
tree for sibling AgentRunLoop freeze candidate absorb.

## Source changes

| File | Change |
|------|--------|
| `Win32IDE_Core.cpp` | SubAgent band bypass; PRE_COMPILER crumb |
| `CompilerIntegration_Real.cpp` | refuse 4110–4119 |
| `CompilerIntegration.cpp` | refuse 4110–4119 |
| `AgentSessionBar.cpp` | control IDs → 48101+ (was 4101–4112) |
| `AgentSessionGuiProof.cpp` | match remapped IDs |
| `auto_feature_registry.cpp` | CHAIN/SWARM SSOT align |
| `vscode_extension_api.cpp` | chain=4110 swarm=4111 |
| `Win32IDE_FeatureManifest.cpp` | chain=4110 swarm=4111 (was dual 4111) |

## Explicit non-claims

- `RUNTIME_REACHED=NOT_RUN` — no tip relink / PathB re-run in this seal
- `ABSORB=NOT_AUTHORIZED` / GhostText NOT_AUTHORIZED
- `TIP_FREEZE_001\bin` untouched
- `PROMOTE=0`
