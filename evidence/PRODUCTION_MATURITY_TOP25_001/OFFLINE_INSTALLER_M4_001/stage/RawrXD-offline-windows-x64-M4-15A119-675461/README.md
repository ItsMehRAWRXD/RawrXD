# RawrXD Offline Install Package (MILESTONE-4)

OFFLINE=1 · CLOUD_MODELS=0 · PROMOTE=0 · CLEAN_VM=0 · NOT_PUBLISHED=1

## What this is
Reproducible local zip that installs tip-pinned CLI + GUI binaries with **no network**
and **no cloud / bundled model weights**.

| Binary | Tip | SHA256 |
|--------|-----|--------|
| rawr.exe | 15A119D1 | 15A119D148572A4B3011AA9A8AFFE605F8FF40D64B7BF83673ECC10A9393C967 |
| RawrXD-Win32IDE.exe | 6754616E | 6754616EA30A566423727F82513AC66D8241FDB73343F9CD7A440FF9D4E43431 |

## Install (offline)
```powershell
Expand-Archive .\RawrXD-offline-windows-x64-M4-15A119-675461.zip -DestinationPath .\rawrxd-offline
pwsh -File .\rawrxd-offline\RawrXD-offline-windows-x64-M4-15A119-675461\scripts\Install-RawrOffline.ps1
# optional: -AddUserPath
```

## Honesty
- CLEAN_VM install witness: **ABSENT** (CLEAN_VM=0)
- winget / Chocolatey / NSIS / MSI: **NOT_PUBLISHED / ABSENT**
- Historical GitHub zip v14.7.3 is a separate download pin — not this tip package
- PROMOTE=0
