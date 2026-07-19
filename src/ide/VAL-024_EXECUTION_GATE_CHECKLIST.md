# VAL-024 Execution Gate Checklist

**Status:** Integration Complete → Execution Validation Phase  
**Date:** 2026-07-19  
**IDE:** RawrXD_IDE_Win32.cpp  
**Runtime:** sovereign_runtime_unified.exe v1.0-ALPHA

---

## ✅ Phase 1: Static Integration (COMPLETE)

| Gate | Requirement | Status | Evidence |
|------|-------------|--------|----------|
| G1 | Source files present | ✅ | RawrXD_IDE_Win32.cpp, .h, SovereignBridge.* |
| G2 | Menu IDs defined | ✅ | IDM_TOOLS_SOVEREIGN_RUN, IDM_TOOLS_VIEW_EVIDENCE |
| G3 | Handler declarations | ✅ | RawrXD_IDE_RunSovereignValidation() declared |
| G4 | Handler implementation | ✅ | Full implementation with runtime discovery |
| G5 | Menu wiring | ✅ | AppendMenuW() in CreateMenuBar() |
| G6 | Accelerator wiring | ✅ | Ctrl+Shift+V in accelTable[] |
| G7 | Runtime executable | ✅ | sovereign_runtime_unified.exe verified |
| G8 | CLI contract | ✅ | --model, --prompt, --autonomous, --validate confirmed |

**Test Result:** 8/8 PASSED ✅

---

## ⏳ Phase 2: Dynamic Execution (PENDING)

### VAL-024.1 — Build Verification

- [ ] Compile IDE with `build_ide_with_sovereign.bat`
- [ ] Verify RawrXD_IDE.exe launches without errors
- [ ] Verify menu appears: Tools → Run Sovereign Validation
- [ ] Verify accelerator works: Ctrl+Shift+V

**Blocker:** Requires MSVC environment (`cl.exe`)

### VAL-024.2 — Runtime Discovery

- [ ] Launch IDE
- [ ] Open any .asm or .cpp file
- [ ] Trigger validation (Ctrl+Shift+V)
- [ ] Verify runtime is discovered at:
  - `d:\rawrxd-ci-bootstrap\src\sovereign\sovereign_runtime_unified.exe`
- [ ] Verify "Launching:" message appears in output panel

### VAL-024.3 — Model Loading

- [ ] Ensure model exists: `models/phi3-mini.gguf`
- [ ] Trigger validation
- [ ] Verify model loads (no "model not found" error)
- [ ] Verify inference begins

**Blocker:** Requires actual GGUF model file

### VAL-024.4 — Evidence Generation

- [ ] Complete validation run
- [ ] Verify `validation/runs/<RUN-ID>/` directory created
- [ ] Verify `certificate.json` exists
- [ ] Verify `manifest.json` exists
- [ ] Verify `telemetry.json` exists

### VAL-024.5 — Result Display

- [ ] Verify output panel shows validation output
- [ ] Verify "SOVEREIGN VALIDATION COMPLETE" message
- [ ] Verify status bar updates
- [ ] Click Tools → View Evidence Bundle
- [ ] Verify evidence summary displayed

### VAL-024.6 — Full Autonomous Loop

- [ ] Edit source file
- [ ] Save (Ctrl+S)
- [ ] Build (F7)
- [ ] Validate (Ctrl+Shift+V)
- [ ] Verify PASS/FAIL result
- [ ] If FAIL, make repair
- [ ] Revalidate
- [ ] Verify PASS

---

## 🔧 Phase 3: Production Hardening (FUTURE)

### Structured JSON Contract

**Current:**
```cpp
BOOL passed = (strstr(buffer, "\"passed\": true") != NULL);
```

**Target:**
```cpp
struct ValidationResult {
    std::string validation_id;  // "VAL-024"
    std::string status;           // "PASS" | "FAIL"
    std::string runtime_version;  // "1.0-ALPHA"
    std::string model;            // "phi3-mini.gguf"
    struct {
        int passed;
        int failed;
    } gates;
    struct {
        double tokens_per_second;
        std::string backend;
    } telemetry;
    std::string evidence_path;
};
```

### Model Selection

**Current:**
```cpp
WCHAR modelPath[MAX_PATH] = L"models/phi3-mini.gguf";
```

**Target:**
- IDE model selector dialog
- Project configuration file (.rawrxd)
- Recent models list
- Model validation (check GGUF integrity)

### Streaming Output

**Current:**
- Capture after execution completes
- 5-minute timeout
- Batch output display

**Target:**
- Real-time streaming
- Live token generation display
- Progress indicators
- Cancel button

### Dashboard Panel

**Current:**
- Output panel text display

**Target:**
```
┌─────────────────────────────────────┐
│ Sovereign Validation Dashboard      │
├─────────────────────────────────────┤
│ Status:    PASS ✅                 │
│ Runtime:   1.0-ALPHA (Vulkan)      │
│ Model:     phi3-mini.gguf           │
│                                      │
│ Gates:     ████████████ 12/12       │
│                                      │
│ Performance:                         │
│   Tokens:  128                      │
│   Speed:   182 tok/s                │
│   Backend: Vulkan                   │
│                                      │
│ [Open Evidence Bundle] [Revalidate] │
└─────────────────────────────────────┘
```

---

## 🎯 Immediate Next Steps

### To Complete VAL-024:

1. **Build IDE**
   ```cmd
   "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
   cd d:\RawrXD\src\ide
   build_ide_with_sovereign.bat
   ```

2. **Obtain Model**
   ```powershell
   # Download phi3-mini GGUF
   curl -L -o models/phi3-mini.gguf \
     https://huggingface.co/microsoft/Phi-3-mini-4k-instruct-gguf/resolve/main/Phi-3-mini-4k-instruct-q4.gguf
   ```

3. **Run End-to-End Test**
   ```
   Launch RawrXD_IDE.exe
   Open: test.asm
   Press: Ctrl+Shift+V
   Verify: PASS + evidence bundle
   ```

---

## 📊 Success Criteria

VAL-024 is complete when:

- [ ] IDE compiles successfully
- [ ] Ctrl+Shift+V triggers validation
- [ ] Runtime executes with actual model
- [ ] Evidence bundle is generated
- [ ] Results display in IDE
- [ ] Full loop: Edit → Build → Validate → Pass

---

## 🏁 Current Status

```
Phase 1: ████████████████████ 100% ✅ COMPLETE
Phase 2: ░░░░░░░░░░░░░░░░░░░░ 0% ⏳ PENDING
Phase 3: ░░░░░░░░░░░░░░░░░░░░ 0% 📋 FUTURE
```

**Integration:** VERIFIED ✅  
**Execution:** READY TO TEST ⏳  
**Production:** PLANNED 📋

---

**Last Updated:** 2026-07-19  
**Next Review:** After VAL-024.6 completion
