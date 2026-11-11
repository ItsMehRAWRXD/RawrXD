# Hotpatch safeguards (tools)

Standalone hash-locked launcher, fail-closed evidence validator, and GhostText
safeguard smoke. Does **not** certify `ROUTING_E2E`.

```text
CERTIFIED=0 PROMOTE=0 ROUTING_E2E=NOT_CERTIFIED BLOCKED_ON_BATCH17_EXE=0 NATIVE_EXE=PRESENT
```

## Run

```powershell
cmd /c `"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat`" && powershell -NoProfile -ExecutionPolicy Bypass -File g:\~dev\rawrxd\tools\hotpatch\Test-HotpatchSafeguards.ps1
```

Evidence: `F:\rawrxd\evidence\UPPER_TIER_MASTER_001\HOTPATCH_SAFEGUARDS_001\`
