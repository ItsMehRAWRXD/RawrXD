# P1 Product-Path Smoke Checklist

**Branch:** `promote/hexmag-p1-ide-product`  
**Policy:** Do not reopen HexMag sequencing / FinalizePolicy.

## Binary gate (after clean rebuild)

- [ ] `RawrXD-Win32IDE.exe` builds from fresh `build-win32ide-p1/`
- [ ] Map/dumpbin shows `HexMag_Init`, `HexMag_Tuner_*`, controller/client TUs linked
- [ ] Record SHA-256 of the exe into `evidence/P1_WIN32IDE_BINARY.txt`

## Product path

| # | Scenario | Pass criteria |
|---|----------|---------------|
| 1 | Launch IDE | Window paints; HexMag link diagnostic on stderr/ODS (`HEXMAG_BACKEND=MASM`) |
| 2 | Load GGUF | Model loads; no Ollama required when native path selected |
| 3 | Normal Copilot send | Message routes; UI leaves “running” |
| 4 | HexMag FINAL | Status `HexMag: FINAL`; answer rendered in Copilot/output |
| 5 | NEED_INPUT → continue | First underspec → NEED_INPUT, no FINAL; second send with details continues |
| 6 | Denied FINAL | Unverified/failed tool cannot show as success FINAL |
| 7 | GGUF fallback | With HexMag down + fallback on → local Ask path |
| 8 | Lifecycle | Close/reopen IDE; second send works; no stuck `m_chatSendInFlight` |

## Not this gate

- Deep2 TPS / numerical parity
- Controller rewrite
- Mutating frozen `HEXMAG_IDE_E2E_001` / `HEXMAG_P0C_INTEGRATION_FREEZE.txt`
