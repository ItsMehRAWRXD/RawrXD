# RAWRXD_VALUE_PACK2 — Integration + Certification Receipt

Date: 2026-09-28 · Drop: F:\~dev\RawrXD_Value_Pack_2\RawrXD_Value_Pack_2\ (17 files, 1,167 LOC)
ZIP SHA-256: 7135BA64A86C32875B8F7C7A74F9EB6370AA26404B4065764D035B3ADD517D27 — MATCH

## Independent certification on this machine (F:\~dev)

```
cmake configure = PASS (VS 2022 x64, _vp2_build)
cmake build     = PASS (after 2 portability fixes below)
ctest           = 1/1 PASS (rawrxd-value-pack2-core)

GATE=RAWRXD_VALUE_PACK2_CORE_001
TASK_STATE=PASS
LIFECYCLE_EVENTS=9
RECEIPT_EXISTS=1
VERDICT=PASS
```

## Browser authority (real Edge, native WinHTTP CDP — no Playwright)

```
GATE=RAWRXD_BROWSER_AUTHORITY_001
LAUNCH=PASS          (headless Edge, DevTools on 9222)
NAVIGATE=PASS
TITLE_READ=PASS      (Runtime.evaluate round-trip)
SCREENSHOT=PASS      (PNG captured via CDP)
CONSOLE_EVENTS=0
NETWORK_FAILURES=0
VERDICT=PASS
```

## Two real defects found + fixed during integration (kept in source)

1. **INTERNET_SCHEME_WSS missing** from this SDK revision → guarded `#define`
   with stable value 22 (winhttp.h). Portability fix, behavior unchanged.
2. **WinHttpCrackUrl fails (12006) on `ws://` scheme** — WinHTTP does not
   recognize the WebSocket scheme. Fix: rewrite `ws://`→`http://` /
   `wss://`→`https://` before cracking; the SECURE flag is derived from the
   ORIGINAL scheme. This was the actual launch blocker (traced via
   GetLastError instrumentation added to openSocket/upgrade steps).
   Instrumentation traces retained (fail-closed diagnostics).

## Boundary honestly preserved (not faked)

```
RAWRXD_IDE_CHAT_DEEP2_E2E_001 = NOT_DECLARED
```

The Win32IDE → Command Center → Agent Session → Deep2 → stream callback →
Win32 Chat UI → BrowserAuthority → merge+receipt last-mile remains open, and
now has all its building blocks certified locally. Wiring = the next step on
the actual tree (drop-in module + RawrXD-Win32IDE link line).

## Integration path (ready, unexecuted)

```cmake
include("${RAWRXD_DROP}/cmake/RawrXDValuePack2.cmake")
target_link_libraries(RawrXD-Win32IDE PRIVATE RawrXD-ValuePack2)
```

OLLAMA_CALLS=0 · STUB_FALLBACKS=0 · PLACEHOLDER_SCAN=PASS