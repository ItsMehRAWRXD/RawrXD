# P1 Product-Path Smoke Checklist

**Branch:** `promote/hexmag-p1-ide-product`  
**Policy:** Do not reopen HexMag sequencing / FinalizePolicy.

## Binary gate (after clean rebuild)

- [x] `RawrXD-Win32IDE.exe` builds from fresh `build-win32ide-p1/`
- [x] Map/dumpbin shows `HexMag_Init`, `HexMag_Tuner_*`, controller/client TUs linked
- [x] Record SHA-256 of the exe into `evidence/P1_WIN32IDE_BINARY.txt`

Frozen: tip `b91641016`, sha256 `D7BD2FFBD23BDFD6DDE2553F05BD1CD7ED38998555D3784603534496F7B24091`
(see `evidence/P1_WIN32IDE_BINARY.txt`).

## Product path

Run against frozen SHA only. Results: `evidence/P1_PRODUCT_PATH_SMOKE/GATE.txt`.

| # | Scenario | Pass criteria | Status (SHA D7BD2FFB…) |
|---|----------|---------------|-------------------------|
| 1 | Launch IDE | Window paints; HexMag link diagnostic on stderr/ODS (`HEXMAG_BACKEND=MASM`) | **FAIL** — `createWindow` abort; MessageBox `Failed to initialize IDE`; trace stops after `Configuration loading complete` |
| 2 | Load GGUF | Model loads; no Ollama required when native path selected | BLOCKED_BY_S1 |
| 3 | Normal Copilot send | Message routes; UI leaves “running” | BLOCKED_BY_S1 |
| 4 | HexMag FINAL | Status `HexMag: FINAL`; answer rendered in Copilot/output | BLOCKED_BY_S1 |
| 5 | NEED_INPUT → continue | First underspec → NEED_INPUT, no FINAL; second send with details continues | BLOCKED_BY_S1 |
| 6 | Denied FINAL | Unverified/failed tool cannot show as success FINAL | BLOCKED_BY_S1 |
| 7 | GGUF fallback | With HexMag down + fallback on → local Ask path | BLOCKED_BY_S1 |
| 8 | Lifecycle | Close/reopen IDE; second send works; no stuck `m_chatSendInFlight` | BLOCKED_BY_S1 |

**OVERALL = FAIL** → do not open P1 PR on this SHA. Next: minimal `createWindow` fix → NEW SHA → rerun 1–8.

## Not this gate

- Deep2 TPS / numerical parity
- Controller rewrite
- Mutating frozen `HEXMAG_IDE_E2E_001` / `HEXMAG_P0C_INTEGRATION_FREEZE.txt`
