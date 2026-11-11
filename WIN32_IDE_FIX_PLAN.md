# Win32 IDE Complete Fix Plan

## Date: 2026-07-08
## Scope: Fix ALL skeleton/stub code in GUI and CLI

---

## COMPLETED FIXES

### 1. ✅ Win32IDE_AIFeatures.cpp → Win32IDE_AIFeatures_Real.cpp
**Status:** REAL implementation created with Ollama HTTP client
- Real HTTP client using WinHTTP
- Connects to localhost:11434
- All AI functions implemented:
  - aiExplainCode
  - aiGenerateTests
  - aiSuggestRefactoring
  - aiFixError
  - aiGenerateFromDescription
  - aiCodeReview
  - aiChat

### 2. ✅ gguf_loader_masm.cpp → gguf_loader_masm_real.cpp
**Status:** REAL implementation created
- Uses actual GGUFLoader class
- Full model loading pipeline
- Metadata extraction
- Validation

---

## PENDING FIXES (Priority Order)

### P0: NativePluginManager.cpp - Editor Wiring
**File:** `src/win32app/NativePluginManager.cpp`
**Lines:** 126-220
**Issue:** All editor operations are stubs
**Fix:** Wire to actual Win32IDE editor instance

```cpp
// Current (stub):
m_api.EditorInsertText = [](...) {
    // TODO: Wire to actual editor
    return 0;
};

// Should be:
m_api.EditorInsertText = [](RawrXD_EditorHandle editor, const char* text, int64_t position) {
    Win32IDE* ide = Win32IDE::GetInstance();
    if (ide && ide->getEditorHwnd()) {
        SendMessage(ide->getEditorHwnd(), EM_SETSEL, position, position);
        SendMessage(ide->getEditorHwnd(), EM_REPLACESEL, 0, (LPARAM)text);
        return 0;
    }
    return -1;
};
```

### P1: NativeToolchainUI.cpp - Settings Dialog
**File:** `src/win32app/NativeToolchainUI.cpp`
**Line:** 433
**Issue:** MessageBox "TODO" instead of real dialog
**Fix:** Create actual settings dialog or call Win32IDE settings

### P2: DAPIntegrationBridge.cpp - Debug UI Updates
**File:** `src/win32app/DAPIntegrationBridge.cpp`
**Lines:** 283-299
**Issue:** TODO comments for debug UI updates
**Fix:** Implement actual panel updates

### P3: ExtensionHost_stub.cpp - Full Implementation
**File:** `src/win32app/ExtensionHost_stub.cpp`
**Issue:** Entire file is stub
**Fix:** Implement extension loading and management

### P4: ExtensionHostIpcBridge.cpp - Full Implementation
**File:** `src/win32app/ExtensionHostIpcBridge.cpp`
**Issue:** Minimal stub
**Fix:** Implement IPC communication

### P5: Win32IDE_VoiceAssistantPanel.cpp - Voice Implementation
**File:** `src/win32app/Win32IDE_VoiceAssistantPanel.cpp`
**Lines:** 234-364
**Issue:** 15+ stub methods
**Fix:** Implement Windows Speech API integration

### P6: BreakpointPropertiesDialog.cpp - Full Dialog
**File:** `src/win32app/BreakpointPropertiesDialog.cpp`
**Line:** 201
**Issue:** TODO for full dialog
**Fix:** Create complete dialog resource

---

## VERIFICATION CHECKLIST

After all fixes:
- [ ] No "TODO" comments in critical paths
- [ ] No "stub" OutputDebugString messages
- [ ] All menu commands call real implementations
- [ ] AI features connect to Ollama
- [ ] GGUF loading uses real loader
- [ ] Plugin API wired to editor
- [ ] Settings dialog opens real UI
- [ ] Debug UI updates properly
- [ ] Voice panel records audio
- [ ] Extensions can load

---

## FILES TO REPLACE

1. `src/win32app/Win32IDE_AIFeatures.cpp` → Use `Win32IDE_AIFeatures_Real.cpp`
2. `src/win32app/gguf_loader_masm.cpp` → Use `gguf_loader_masm_real.cpp`

## FILES TO MODIFY

1. `src/win32app/NativePluginManager.cpp` - Wire editor operations
2. `src/win32app/NativeToolchainUI.cpp` - Implement settings dialog
3. `src/win32app/DAPIntegrationBridge.cpp` - Implement debug UI updates
4. `src/win32app/ExtensionHost_stub.cpp` - Full implementation
5. `src/win32app/ExtensionHostIpcBridge.cpp` - Full implementation
6. `src/win32app/Win32IDE_VoiceAssistantPanel.cpp` - Implement voice
7. `src/win32app/BreakpointPropertiesDialog.cpp` - Complete dialog

---

## BUILD VERIFICATION

After fixes:
```bash
cd d:\rawrxd\build
cmake --build . --target RawrXD-Win32IDE
```

Test:
```bash
.\bin\RawrXD-Win32IDE.exe --selftest
```
