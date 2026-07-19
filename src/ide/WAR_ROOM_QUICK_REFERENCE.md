# War Room Quick Reference

## Sovereign Bridge — Production Status

**Integration:** ✅ VERIFIED  
**Execution:** ⏳ READY TO TEST  
**Command:** `Ctrl+Shift+V`

---

## 30-Second Status

```
RawrXD_IDE_Win32.cpp
    |
    | ✅ Menu: Tools → Run Sovereign Validation
    | ✅ Accelerator: Ctrl+Shift+V
    | ✅ Handler: RawrXD_IDE_RunSovereignValidation()
    | ✅ Runtime: sovereign_runtime_unified.exe
    | ✅ Evidence: validation/runs/<RUN-ID>/
    |
    ↓
PRODUCTION READY
```

---

## Key Files

| File | Purpose | Status |
|------|---------|--------|
| `RawrXD_IDE_Win32.cpp` | Main IDE | ✅ Complete |
| `SovereignBridge.hpp` | Bridge header | ✅ Complete |
| `SovereignBridge.cpp` | Bridge impl | ✅ Complete |
| `sovereign_runtime_unified.exe` | Runtime | ✅ Verified |
| `test_sovereign_integration.ps1` | Tests | ✅ Pass |

---

## Quick Commands

### Verify Integration
```powershell
cd d:\RawrXD\src\ide
powershell -ExecutionPolicy Bypass -File test_sovereign_integration.ps1
```

### Build IDE
```cmd
"C:\VS2022Enterprise\VC\Auxiliary\Build\vcvars64.bat"
cd d:\RawrXD\src\ide
build_ide_with_sovereign.bat
```

### Test Runtime
```cmd
cd d:\rawrxd-ci-bootstrap\src\sovereign
sovereign_runtime_unified.exe --help
```

---

## Architecture

```
User presses Ctrl+Shift+V
        |
        ↓
WM_COMMAND → IDM_TOOLS_SOVEREIGN_RUN
        |
        ↓
RawrXD_IDE_RunSovereignValidation()
        |
        ├── Save file
        ├── Find runtime (6 paths)
        ├── Build command line
        └── Launch process
                |
                ↓
    sovereign_runtime_unified.exe
                |
                ├── Load GGUF
                ├── Run inference
                ├── Generate certificate
                └── Write evidence
                |
                ↓
    IDE captures output
                |
                ↓
    Display results
```

---

## Runtime Discovery Paths

1. `rawrxd.exe`
2. `..\..\rawrxd.exe`
3. `..\..\..\rawrxd.exe`
4. `d:\rawrxd-ci-bootstrap\build\rawrxd.exe`
5. `d:\rawrxd-ci-bootstrap\rawrxd.exe`
6. `d:\rawrxd-ci-bootstrap\src\sovereign\sovereign_runtime_unified.exe` ✅

---

## CLI Contract

```
sovereign_runtime_unified.exe \
    --model <path> \
    --prompt <text> \
    --max-tokens 128 \
    --autonomous \
    --validate
```

---

## Evidence Bundle Structure

```
validation/
└── runs/
    └── 20260719-143052-ABC123/
        ├── manifest.json
        ├── certificate.json
        ├── telemetry.json
        └── hardware.json
```

---

## Menu Locations

```
Tools
 ├── PE Inspector
 ├── Instruction Encoder
 ├── Extension Manager
 ├── ────────────────
 ├── Run Sovereign Validation  ← Ctrl+Shift+V
 ├── View Evidence Bundle
 └── Options
```

---

## Status Bar Parts

| Part | Content |
|------|---------|
| SB_PART_FILE | Current file path |
| SB_PART_LINECOL | Line X, Col Y |
| SB_PART_ENCODING | UTF-8 / ANSI |
| SB_PART_BUILD | Build / Sovereign status |
| SB_PART_IPC | IPC connection state |

---

## Known Blockers

| Issue | Solution |
|-------|----------|
| No MSVC | Install VS2022 or use pre-built binary |
| No model | Download phi3-mini.gguf |
| Timeout | Increase TIMEOUT_MS constant |

---

## Success Indicators

✅ **Integration Complete:**
- Menu appears
- Shortcut works
- Handler fires

✅ **Execution Ready:**
- Runtime discovered
- Process launches
- Output captured

✅ **Production:**
- Model loads
- Inference runs
- Evidence generated
- Results displayed

---

## Emergency Contacts

| Issue | Check |
|-------|-------|
| Menu missing | Verify IDM_TOOLS_SOVEREIGN_RUN defined |
| Shortcut fails | Check accelerator table |
| Runtime not found | Check 6 discovery paths |
| No output | Verify pipe creation |
| Timeout | Check model exists |

---

## One-Line Summary

> **Press Ctrl+Shift+V to validate any code with the Sovereign Runtime.**

---

**Last Updated:** 2026-07-19  
**Status:** READY FOR WAR-ROOM DEPLOYMENT
