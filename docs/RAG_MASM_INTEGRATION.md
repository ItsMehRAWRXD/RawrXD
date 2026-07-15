# MASM x64 Integration Guide
## RawrXD Voice Assistant RAG - Pure Assembly Bridge

**Date:** 2026-06-20  
**Architecture:** C++ RAG Core ↔ C Bridge API ↔ MASM x64

---

## Overview

The RAG (Retrieval-Augmented Generation) pipeline is implemented in C++ but needs to be accessible from pure MASM x64 code. This is achieved through a **C-compatible bridge layer** that exposes the functionality via `extern "C"` functions.

### Architecture Flow

```
┌─────────────────────────────────────────────────────────────┐
│                    MASM x64 Application                      │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  voice_assistant_masm.asm                            │  │
│  │  • Initialize manager                                │  │
│  │  • Call C bridge functions                             │  │
│  │  • Process JSON responses                              │  │
│  └────────────────────┬─────────────────────────────────┘  │
└───────────────────────┼──────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│                    C Bridge Layer                            │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  voice_assistant_masm_bridge.hpp/cpp                 │  │
│  │  • C-compatible function declarations                │  │
│  │  • Opaque handles (void*) for MASM                  │  │
│  │  • JSON string marshalling                           │  │
│  └────────────────────┬─────────────────────────────────┘  │
└───────────────────────┼──────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│                    C++ RAG Core                              │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  voice_assistant_manager.cpp                         │  │
│  │  voice_assistant_types.cpp                           │  │
│  │  • Full C++ implementation                           │  │
│  │  • nlohmann::json for responses                      │  │
│  │  • PIMPL pattern for extensibility                   │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

---

## C Bridge API Reference

### Manager Lifecycle

```c
// Create manager instance
VoiceAssistantManagerHandle VoiceAssistant_CreateManager(void);

// Destroy manager
void VoiceAssistant_DestroyManager(VoiceAssistantManagerHandle handle);

// Check if ready
int VoiceAssistant_IsReady(VoiceAssistantManagerHandle handle);
```

### RAG Queries

```c
// Execute semantic code query
JsonResponseHandle VoiceAssistant_QueryCodebase(
    VoiceAssistantManagerHandle manager,
    const char* query,           // Natural language query
    const char* current_file,    // Current file path (can be NULL)
    int current_line             // Current line number
);

// Process voice input
JsonResponseHandle VoiceAssistant_ProcessVoiceInput(
    VoiceAssistantManagerHandle manager,
    const char* text,            // Voice input text
    const char* assistant_type,  // "siri", "alexa", or "hybrid"
    const char* session_id       // Session ID (can be NULL)
);
```

### IDE Actions

```c
// Dispatch IDE action
JsonResponseHandle VoiceAssistant_DispatchIDEAction(
    VoiceAssistantManagerHandle manager,
    const char* intent_id        // e.g., "ide_build", "ide_run"
);

// Check if action available
int VoiceAssistant_HasIDEAction(
    VoiceAssistantManagerHandle manager,
    const char* intent_id
);
```

### JSON Response Handling

```c
// Get string value
int VoiceAssistant_JsonGetString(
    JsonResponseHandle json,
    const char* key,
    char* buffer,
    size_t buffer_size
);

// Get integer value
int VoiceAssistant_JsonGetInt(
    JsonResponseHandle json,
    const char* key,
    int* value
);

// Get array size
int VoiceAssistant_JsonGetArraySize(JsonResponseHandle json, const char* key);

// Free JSON response
void VoiceAssistant_FreeJson(JsonResponseHandle json);
```

---

## MASM Usage Example

### Initialize Manager

```asm
; Create manager instance
sub     rsp, 40
call    VoiceAssistant_CreateManager
test    rax, rax
jz      init_failed
mov     hManager, rax           ; Save handle

; Set context analyzer
mov     rcx, hManager
lea     rdx, szProjectPath
call    VoiceAssistant_SetContextAnalyzer
```

### Execute RAG Query

```asm
; Query codebase
mov     rcx, hManager
lea     rdx, szQuery           ; "find all functions"
lea     r8, szCurrentFile      ; "src/main.cpp"
mov     r9d, 42                ; Line number
call    VoiceAssistant_QueryCodebase
mov     hJsonResponse, rax

; Get status from JSON
mov     rcx, hJsonResponse
lea     rdx, szKeyStatus       ; "status"
lea     r8, jsonBuffer
mov     r9, 4096
call    VoiceAssistant_JsonGetString

; Free response
mov     rcx, hJsonResponse
call    VoiceAssistant_FreeJson
```

### Dispatch IDE Action

```asm
; Check if action available
mov     rcx, hManager
lea     rdx, szIntentBuild     ; "ide_build"
call    VoiceAssistant_HasIDEAction
test    rax, rax
jz      no_action

; Dispatch action
mov     rcx, hManager
lea     rdx, szIntentBuild
call    VoiceAssistant_DispatchIDEAction
mov     hJsonResponse, rax

; Process response...
```

---

## Build Instructions

### 1. Build C++ Bridge DLL

```bash
cl.exe /EHsc /std:c++17 /LD /I d:\rawrxd\include /I d:\rawrxd\src\core /I d:\rawrxd\src\win32app \
    voice_assistant_masm_bridge.cpp \
    voice_assistant_manager.cpp \
    voice_assistant_types.cpp \
    /link /OUT:voice_assistant_masm_bridge.dll
```

### 2. Assemble MASM Code

```bash
ml64.exe /c /Fo voice_assistant_masm.obj voice_assistant_masm.asm
```

### 3. Link MASM with Bridge

```bash
link.exe voice_assistant_masm.obj \
    voice_assistant_masm_bridge.lib \
    kernel32.lib \
    /OUT:voice_assistant_demo.exe
```

---

## Calling Convention

### C Bridge Functions (x64)

All C bridge functions use the **Microsoft x64 calling convention**:

- **RCX** - First integer/pointer argument
- **RDX** - Second integer/pointer argument
- **R8** - Third integer/pointer argument
- **R9** - Fourth integer/pointer argument
- **Stack** - Additional arguments (right to left)
- **RAX** - Return value
- **R10, R11** - Scratch registers
- **RBX, RBP, RDI, RSI, R12-R15** - Callee-saved

### Shadow Space

Caller must allocate 32 bytes of shadow space before each call:

```asm
sub     rsp, 40         ; 32 bytes shadow + 8 bytes alignment
call    SomeFunction
add     rsp, 40
```

---

## Memory Management

### MASM Responsibilities

1. **Allocate buffers** for string outputs
2. **Free JSON responses** with `VoiceAssistant_FreeJson`
3. **Free strings** with `VoiceAssistant_FreeString`
4. **Destroy manager** with `VoiceAssistant_DestroyManager`

### Example Cleanup

```asm
cleanup:
    ; Free JSON if allocated
    mov     rcx, hJsonResponse
    test    rcx, rcx
    jz      no_json
    call    VoiceAssistant_FreeJson
no_json:

    ; Destroy manager
    mov     rcx, hManager
    call    VoiceAssistant_DestroyManager
    
    ; Exit
    xor     ecx, ecx
    call    ExitProcess
```

---

## Error Handling

### Get Last Error

```asm
; After failed call
lea     rcx, errorBuffer
mov     rdx, 1024
call    VoiceAssistant_GetLastError

; Print error
lea     rcx, errorBuffer
call    PrintString
```

### Common Error Codes

| Error | Cause | Solution |
|-------|-------|----------|
| "Invalid manager handle" | NULL handle passed | Check CreateManager return |
| "Analyzer not ready" | Context analyzer not set | Call SetContextAnalyzer |
| "Invalid parameters" | NULL required parameter | Check all arguments |
| JSON parse error | Corrupted JSON | Check FreeJson not called twice |

---

## Integration with Win32IDE_Main.asm

### Recommended Integration Points

```asm
; In Win32IDE_Main.asm initialization
WinMain PROC
    ; ... existing initialization ...
    
    ; Initialize Voice Assistant
    call    InitializeVoiceAssistant
    test    rax, rax
    jz      va_init_failed
    mov     g_hVoiceAssistant, rax
    
    ; ... continue with main message loop ...
    
WinMain ENDP

; In message handler
WndProc PROC
    ; ... existing message handling ...
    
    cmp     uMsg, WM_VOICE_COMMAND
    jne     not_voice_command
    
    ; Process voice command
    mov     rcx, g_hVoiceAssistant
    mov     rdx, lParam           ; Voice text
    call    ProcessVoiceCommand
    
not_voice_command:
    ; ... continue with default handling ...
    
WndProc ENDP
```

---

## Performance Considerations

### Latency Expectations

| Operation | Expected Latency |
|-----------|------------------|
| CreateManager | ~1-5ms |
| QueryCodebase | ~10-100ms (depends on index) |
| ProcessVoiceInput | ~5-20ms |
| DispatchIDEAction | ~1-5ms |
| JSON Get String | ~0.1-1ms |

### Optimization Tips

1. **Reuse manager** - Don't create/destroy per query
2. **Buffer reuse** - Allocate JSON buffers once
3. **Batch operations** - Group multiple queries
4. **Async processing** - Use worker threads for queries

---

## Debugging

### Enable Debug Output

```asm
; In MASM code
call    VoiceAssistant_GetLastError
lea     rcx, errorBuffer
call    OutputDebugStringA
```

### Check JSON Response

```asm
; Print full JSON for debugging
mov     rcx, hJsonResponse
; (JSON handle is actually a pointer to string)
mov     rcx, [rcx]              ; Dereference to get string
call    OutputDebugStringA
```

---

## Summary

The MASM x64 integration provides:

✅ **Full RAG functionality** from pure assembly  
✅ **C-compatible API** with opaque handles  
✅ **JSON response handling** with string marshalling  
✅ **IDE action dispatch** for voice commands  
✅ **Error handling** with descriptive messages  
✅ **Memory management** with explicit free functions  

**The bridge enables the MASM-based Win32IDE to leverage the full power of the C++ RAG pipeline while maintaining the pure assembly architecture.**

---

**Files:**
- `voice_assistant_masm_bridge.hpp` - C API declarations
- `voice_assistant_masm_bridge.cpp` - C API implementation
- `voice_assistant_masm.asm` - MASM demonstration
- `RAG_MASM_INTEGRATION.md` - This documentation
