# CONPTY_STREAM_OWNER_001 — tip 748B disposition

```
ASOF_UTC=2026-10-28T17:12:00Z
PROMOTE=0 TIP_CLIMB=HOLD CERTIFIED=0 NO_INVENT_PASS=1
AUTHORITY_SHA=748B210A8F17C6C47685BE1E2718CB0113C070E47881AD3A76B2EBB013934145
```

## Tip bind

| Marker | In tip 748B |
|--------|-------------|
| CreatePseudoConsole | yes |
| CONPTY_STREAM_OWNER | yes |
| GateConPty FAIL_CLOSED | yes |
| CreatePseudoConsole_absent | yes |

Product owner remains `Win32TerminalManager` (PowerShell panel / tab.manager).

## RUNTIME

| Facet | Result |
|-------|--------|
| CreatePseudoConsole API smoke (attr list + cmd) | RUNTIME_REACHED=1 (mirror; ≠ HWND) |
| HWND PowerShell panel `m_dedicatedPowerShellTerminal->start` | NOT_RUN |
| EmbeddedTerminal pipe-as-ConPTY | FAIL_CLOSED in source (RELINK_PENDING candidate) |

Smoke log: `logs/conpty_owner_smoke_run.txt`

## Explicit non-claims

```
HWND_CONPTY_E2E=NOT_RUN
CERTIFIED=0
PROMOTE=0
API_SMOKE_NE_PRODUCT_HWND=1
```
