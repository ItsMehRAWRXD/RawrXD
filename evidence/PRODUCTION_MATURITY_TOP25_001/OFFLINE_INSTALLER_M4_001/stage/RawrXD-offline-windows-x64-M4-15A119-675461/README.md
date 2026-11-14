# RawrXD Offline Install Package (MILESTONE-4)

OFFLINE=1 · CLOUD_MODELS=0 · PROMOTE=0 · CLEAN_VM=0 · NOT_PUBLISHED=1
SETUPWIZARD=REAL_COPYFILE · VSIX bundled · rollback script included

## What this is
Reproducible local zip that installs tip-pinned CLI + GUI + SetupWizard + VSIX
with **no network** and **no cloud / bundled model weights**.

| Artifact | Tip / note | SHA256 |
|----------|------------|--------|
| rawr.exe | 15A119D1 | 15A119D148572A4B3011AA9A8AFFE605F8FF40D64B7BF83673ECC10A9393C967 |
| RawrXD-Win32IDE.exe | 6754616E | 6754616EA30A566423727F82513AC66D8241FDB73343F9CD7A440FF9D4E43431 |
| SetupWizard.exe | real CopyFile | 7F02B17A80BC3B4236545E4196FF49069DCC4F3DDE2E61D9839721E2A6D79707 |
| rawrxd-lsp-client-0.1.0.vsix | bundled | F45DA0FED6C4780DD986BC1B59582BA772B91A7D5ABBBA5D4718302E56A39B6C |

## Install (offline)
```powershell
Expand-Archive .\RawrXD-offline-windows-x64-M4-15A119-675461.zip -DestinationPath .\rawrxd-offline
pwsh -File .\rawrxd-offline\RawrXD-offline-windows-x64-M4-15A119-675461\scripts\Install-RawrOffline.ps1
# or: .\SetupWizard.exe /install /silent /target=$env:LOCALAPPDATA\RawrXD\offline-M4
```

## Rollback
```powershell
pwsh -File .\rawrxd-offline\RawrXD-offline-windows-x64-M4-15A119-675461\scripts\Uninstall-RawrOffline.ps1
```

## Honesty
- CLEAN_VM install witness: **ABSENT** (CLEAN_VM=0); sandbox measure separate
- winget / Chocolatey / NSIS / MSI: **NOT_PUBLISHED / ABSENT**
- PROMOTE=0
