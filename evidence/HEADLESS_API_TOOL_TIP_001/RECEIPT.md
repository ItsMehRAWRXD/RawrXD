# RECEIPT — HEADLESS_API_TOOL_TIP_001

```
ASOF_UTC=2026-10-28T11:02:18Z
WORKSPACE=G:\~dev\rawrxd
PROMOTE=0 TIP_CLIMB=HOLD CERTIFIED=0
NO_INVENT_PASS=1 NO_REBUILD=1 LOCAL_ONLY=1
GATE=G16 Headless /api/tool
TIP_SHA=6832F439100C71AE7923A7736F71784039B7F6A9DE53C895E56E9C7932A9F8B2
```

## Verdict

| Gate | Result |
|------|--------|
| TIP_SHA_MATCH | **PASS** (`6832F439…`) |
| Local-only bind (`--local --bind 127.0.0.1`) | **PASS** |
| Authorized `/api/tool` POS (`read_motd` + `list_directory`) | **PASS** (HTTP 200) |
| Remote/non-local Origin NEG | **PASS** (`origin_denied` HTTP 403) |
| Bare no-key fail-closed | **503** `authentication_not_configured` (documented; not invent PASS) |
| `execute_command` | **HTTP 500** (not claimed) |
| G16 | **MET** |
| PROMOTE | **0** |

## Tip EXE

| Field | Value |
|-------|-------|
| Path | `G:\~dev\rawrxd\build_win32ide_link001\bin\RawrXD-Win32IDE.exe` |
| SHA256 | `6832F439100C71AE7923A7736F71784039B7F6A9DE53C895E56E9C7932A9F8B2` |
| Rebuild | **NO** |

## Live path

1. Bare tip headless (no `RAWRXD_HOSTED_API_KEY`) → `POST /api/tool` **503** `authentication_not_configured` (`logs/bare_nokey.*`).
2. Same tip with ephemeral `RAWRXD_HOSTED_API_KEY` + scopes (runtime env only):
   - Origin `https://evil.example` / `null` → **403** `{"error":"origin_denied"}` (`logs/R_evil.body.txt`, `logs/R_null.body.txt`).
   - `read_motd` → **200** MOTD content (`logs/04_read_motd.*`, `logs/B_motd.*`).
   - `list_directory` → **200** entries (`logs/05_post_list.*`, `logs/B_list.*`).
   - Loopback Origin `http://127.0.0.1:<port>` → **200**.
3. Ports exercised: 18772 / 18773 / 18774 / 18775 (all `127.0.0.1`).

## Artifacts

- `LAW.txt` `RECEIPT.md`
- `logs/e2e_lines.txt` `logs/e2e_round2.txt` `logs/e2e_round3.txt`
- `logs/bare_nokey.txt` `logs/R_evil.body.txt` `logs/R_null.body.txt`
- `logs/04_read_motd.body.txt` `logs/05_post_list.body.txt`
- `logs/server*_stdout.txt` `logs/exe_sha_*.txt`

## Historical / non-claims

```
HEADLESS_TOOL_ROUTES_001 / G3_HEADLESS_API_TOOL_* = HISTORICAL_SHA_ONLY
execute_command HTTP 500 != PASS
BARE_503 != invent PASS (auth not configured)
PROMOTE=0 TIP_CLIMB=HOLD CERTIFIED=0 PERFECT=0
No SubAgent / ShellLayout / ToolActionStatus source edits
No tip rebuild
```
