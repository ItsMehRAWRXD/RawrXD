# RECEIPT — HEADLESS_API_TOOL_TIP_748B_001

```
ASOF_UTC=2026-10-28T17:12:00Z
WORKSPACE=G:\~dev\rawrxd
PROMOTE=0 TIP_CLIMB=HOLD CERTIFIED=0
NO_INVENT_PASS=1 REBUILD=0 LOCAL_ONLY=1
GATE=G16 + critical ToolRoutes E2E on tip 748B
TIP_SHA=748B210A8F17C6C47685BE1E2718CB0113C070E47881AD3A76B2EBB013934145
GHOSTTEXT_ABSORB=NOT_AUTHORIZED
```

## Verdict

| Gate | Result |
|------|--------|
| TIP_SHA_MATCH | PASS (`748B210A…`) |
| G16 MOTD+list + evil Origin | MET (200/200/403) |
| read_file / write_file / safe_write_* | RUNTIME 200 |
| list_dir alias | RUNTIME 200 |
| search_files | RUNTIME 200 |
| grep_files (tip) | FAIL_CLOSED 400 `unknown_tool` |
| execute_command no grant | FAIL_CLOSED 403 |
| execute_command grant | RUNTIME 200 |
| deny abs / `..` write | FAIL_CLOSED 403 |
| bare no-key (unset) | HTTP 200 `RUNTIME_UNAUTH_LOCAL` (documented ≠ invent PASS) |
| PROMOTE | **0** |

## Tip EXE

| Field | Value |
|-------|-------|
| Path | `evidence/TIP_FREEZE_001/bin/RawrXD-Win32IDE.exe` |
| SHA256 | `748B210A8F17C6C47685BE1E2718CB0113C070E47881AD3A76B2EBB013934145` |
| Rebuild / freeze clobber | **NO** |

## Artifacts

- `ROUTE_TABLE.txt` `SUMMARY.txt` `LAW.txt`
- `harness_routes_e2e.ps1` (curl.exe client)
- `logs/R_*.{code,body,hdr}.txt` `logs/scoreboard.txt`
- Grant retry: `logs/R_exec_grant.*` port 18992

## Non-claims

```
PROMOTE=0 TIP_CLIMB=HOLD CERTIFIED=0
grep alias SOURCE_WIRED only until new freeze
BARE_200 != invent authentication PASS
name/arguments schema ≠ product (tool/args required)
Prior 6832F439 G16 seal = HISTORICAL_SHA_ONLY
```
