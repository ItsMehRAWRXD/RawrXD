# RECEIPT — HEADLESS_TOOL_ROUTES_001

```
PROMOTE=0
TIP_CLIMB=HOLD
CERTIFIED=0
LOCAL_ONLY=1
OLLAMA_HTTP=0
WORKSPACE=G:\~dev\rawrxd
ASOF_UTC=2026-10-28T08:30:00Z
DISPOSITION=GATED_LOCAL_ONLY
```

## Verdict

| Gate | Result |
|------|--------|
| EXE SHA 89BFD614… | `SHA_MATCH=1` |
| Route inventory (ToolRoutes.cpp) | Documented in LAW + `logs/route_inventory_from_source.txt` |
| Sealed EXE string wire (`/api/tool`, MOTD) | `SOURCE_WIRED=1` |
| HTTP MOTD file/command ladder | `GATED_LOCAL_ONLY` → `NOT_RUN` (not PASS) |
| In-process `--no-server` boot | Observed EXIT=0 + server-disabled warn |
| PROMOTE | 0 |

## Sealed EXE

| Field | Value |
|-------|-------|
| Path | `G:\~dev\rawrxd\build_win32ide_link001\bin\RawrXD-Win32IDE.exe` |
| SHA256 | `89BFD6142CEE7A6AA537DF0297014E240C7CC55B142C230521527914469F8630` |
| Size | 331629056 |
| Relink | NO |

## GATED_LOCAL_ONLY cite

Sealed entry from `evidence/LIVE_TETRAD_POST_CAMELLIA_001/LAW.txt`:

`MODE=--local --no-server --prompt <text> --model <gguf> --max-tokens N --backend local`

`HeadlessIDE::runServerMode` with `--no-server` exits before any `/api/tool` HostedHttpRequest. `executeToolRepl` has no REPL/stdin entry (help lists no tool commands). Therefore the real MOTD-gated file/command HTTP path was not exercised; fail-closed: `NOT_RUN != PASS`.

## In-process smoke (ran)

```
RawrXD-Win32IDE.exe --headless --local --no-server --dir G:\~dev\rawrxd
EXIT=0
stderr: Server disabled (--no-server); nothing to serve, exiting.
```

## Routes (summary)

POST `/api/tool` (+ `/run-tool`), file/command siblings → `read_motd` / `read_file` / `write_file` / `list_directory` / `execute_command` / `git_status` / R04 FS aliases. MOTD gate: `motd_required` until MOTD read.

## Paths

- `evidence/HEADLESS_TOOL_ROUTES_001/LAW.txt`
- `evidence/HEADLESS_TOOL_ROUTES_001/RECEIPT.md`
- `evidence/HEADLESS_TOOL_ROUTES_001/logs/exe_route_strings.txt`
- `evidence/HEADLESS_TOOL_ROUTES_001/logs/route_inventory_from_source.txt`
- `evidence/HEADLESS_TOOL_ROUTES_001/logs/no_server_stdout.txt`
- `evidence/HEADLESS_TOOL_ROUTES_001/logs/no_server_stderr.txt`

## Explicit non-actions

- Ollama HTTP not reopened
- Inference SPLIT not flipped
- No synthetic HTTP tool PASS
