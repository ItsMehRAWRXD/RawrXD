# RawrXD Agent T15 Assessment (reconciled)

ASOF_UTC=2026-11-03T15:04:30Z
SCOPE=rawr.exe local agent (â‰  Win32IDE CERT SHA certification)
AUTHORITY_DISK=`T15_DISK_VERIFY.md`
AUTHORITY_HARNESS=`RECEIPT.md`

## Tool / runtime (log)

| Test | Result |
|------|--------|
| Startup / MOTD / routing | PASS |
| `readFile` + marker quote | PASS |
| `editFiles` tool exit 0 | PASS |
| `file_changed` | PASS (log) |
| Agent run completion | PASS |

## Disk content (independent reopen â€” already executed)

```
MARKER_PRESENT=False
BEFORE_EQUALS_ONE=True
SHA256=0072479256D2F56220995BD21727CC30220E445AF1792145947084D96EE9CCB1
```

File still: `int before = 1;` â€” edited marker `T15_EDITED_T15_7bb4df317c` **absent**.

## Controlling disposition

```
AGENT_READFILE=PASS
AGENT_EDITFILES_TOOL=PASS
AGENT_FILE_CHANGED_EVENT=PASS
AGENT_EDIT_CONTENT_VERIFICATION=FAIL
AGENT_EDIT_CONTENT_VERIFICATION_WAS=OPEN
AGENT_T15=PARTIAL_PASS
T15_FULL_ACCEPTANCE=PENDING

BATCH1_CANCEL_RECOVERY=DEFERRED
WIN32IDE_ACTIVE_SHA=3B720981EC567D60461B874F0C1EE46E03F85DB58F6E1788CBEE31F8B2CCAD5F
REBUILD=HELD
PROMOTE=0
CERTIFIED=0
```

Tool success â‰  durable intended bytes. Independent hash/content check closed verification as **FAIL**, not left OPEN.
Does not pass Win32IDE Cancel recovery or authorize PROMOTE.
