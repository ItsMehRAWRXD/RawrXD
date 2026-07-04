# Phase 5: Win32IDE Hotpatch Integration

## Overview

Phase 5 integrates the Epoch-RCU hotpatch system into the Win32IDE, enabling live model swapping during coding sessions without restarting the IDE.

## Architecture

### Components

1. **IDEHotpatchIntegration** (`Win32IDE_HotpatchIntegration.hpp/cpp`)
   - Singleton integration layer between IDE and hotpatch router
   - Monitors hotpatch completion in background thread
   - Provides C API for MASM bridge callbacks
   - Sends window messages to IDE for UI updates

2. **Menu Integration** (`Win32IDE_LinkFixes.cpp`)
   - `ID_TOOLS_HOTPATCH` (8050): Request new model hotpatch
   - `ID_TOOLS_HOTPATCH_STATUS` (8051): Show hotpatch status dialog
   - File picker for GGUF model selection
   - Status display showing epoch, active/pending models

3. **Resource IDs** (`resource.h`)
   - Added hotpatch menu items in Tools menu range (8001-8099)

## User Flow

```
1. User clicks Tools → Hotpatch Model
   └─> File picker dialog opens
   └─> User selects GGUF model
   └─> IDEHotpatchIntegration::RequestHotpatch(path)
   └─> RawrXD_RequestHotpatch() called

2. Background Monitor Thread
   └─> Polls RawrXD_IsSwapPending()
   └─> Detects completion
   └─> Posts WM_USER+0x700 to IDE window
   └─> Updates active model path

3. IDE Window receives WM_USER+0x700
   └─> Updates status bar
   └─> Shows completion notification
   └─> New model active for inference
```

## Files Added/Modified

### New Files
- `src/win32app/Win32IDE_HotpatchIntegration.hpp` - Integration interface
- `src/win32app/Win32IDE_HotpatchIntegration.cpp` - Implementation
- `docs/phase5_win32ide_integration.md` - This document

### Modified Files
- `src/win32app/resource.h` - Added menu IDs
- `src/win32app/Win32IDE_LinkFixes.cpp` - Menu handlers and integration

## Menu Structure

```
Tools
├── Options...        (ID_TOOLS_OPTIONS: 8001)
├── Plugins...      (ID_TOOLS_PLUGINS: 8002)
├── Extensions...   (ID_TOOLS_EXTENSIONS: 8003)
├── Settings...     (ID_TOOLS_SETTINGS: 8004)
├── ────────────────
├── Hotpatch Model...       (ID_TOOLS_HOTPATCH: 8050) [NEW]
└── Hotpatch Status...      (ID_TOOLS_HOTPATCH_STATUS: 8051) [NEW]
```

## C API for MASM Bridge

```c
// Called from MASM router when hotpatch completes
void RawrXD_IDE_OnHotpatchComplete(const char* modelPath, int success);

// Called from MASM router to get current IDE model
const char* RawrXD_IDE_GetActiveModelPath();
```

## Window Messages

- `WM_USER + 0x700` - Hotpatch complete notification
  - `wParam`: 1 = success, 0 = failure
  - `lParam`: const char* to model path

## Status Dialog

Shows:
- Current epoch counter
- Whether swap is pending
- Active model path
- Pending model path (if any)

## Next Steps

1. **Build Integration**: Add new files to CMakeLists.txt for Win32IDE target
2. **UI Polish**: Add progress indicator during hotpatch
3. **Error Handling**: Show error dialogs on hotpatch failure
4. **Model Validation**: Verify GGUF format before hotpatch request
5. **Auto-Reload**: Option to auto-reload last model on IDE startup

## Verification

```cpp
// Test hotpatch integration
RawrXD::IDEHotpatchIntegration::Instance().Initialize(ide);
bool ok = RawrXD::IDEHotpatchIntegration::Instance().RequestHotpatch("model.gguf");
auto status = RawrXD::IDEHotpatchIntegration::Instance().GetStatus();
```

## Status

🔄 **IN PROGRESS** - Core integration complete, needs CMake wiring and UI polish
