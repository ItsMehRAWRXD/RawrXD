# On-disk candidate snapshot

ASOF_UTC=2026-11-09T06:50:00Z
PROMOTE=0

```
EXE=F:\rawrxd\build_progression_finish25\bin\RawrXD-Win32IDE-Native.exe
SHA256=18FA04F9CAA2BC762279DE7C1AC30DEEBD83D357BCD0133ABFEC2F043E531E68
SIZE=2509824
LINK_PROFILE=SLIM_WIN32IDE_DEEP2_LINKED_OPTREF
VERIFY=certutil SHA256 (this session)
```

## Drift / rollback

| SHA | Size | Role |
|-----|------|------|
| 18FA04F9… | 2509824 | **Active** daily-use candidate |
| 7EEE4427… | 4065280 | Accidental diag rebuild — do not use |
| 4ED342CE… | 2509824 | Locked crash-era seal — absent on disk |
| 323A38A0… | 2509312 | Recorded in older `PROGRESSION…\BINARY_HASH.txt` — **≠ on-disk** |

```
ROLLBACK=F:\rawrxd\evidence\PROGRESSION_FINISH25_001\CANCEL\logs\RawrXD-Win32IDE-Native.exe.18FA04F9.bak
BINARY_HASH_TXT_MISMATCH=1  # PROGRESSION_FINISH25_001\BINARY_HASH.txt may still cite 323A38A0…
ON_DISK_AUTHORITY=THIS_FILE + certutil
```
