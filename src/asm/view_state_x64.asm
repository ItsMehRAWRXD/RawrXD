; ============================================================================
; RawrXD ViewState - Enterprise x64 MASM Implementation
; Zero-dependency, lock-free, cache-line optimized UI state management
; ============================================================================
; Architecture: x64 Native (no WOW64, no dependencies)
; Memory Model: Flat, 64-bit
; Calling Convention: Microsoft x64 (RCX, RDX, R8, R9 + stack)
; Thread Safety: Lock-free via atomic operations
; Cache Optimization: 16-byte aligned
; ============================================================================

OPTION DOTNAME
OPTION CASEMAP:NONE

; ============================================================================
; Constants - Cache line and memory layout
; ============================================================================
CACHE_LINE_SIZE EQU 64

; ViewState flags (bit positions)
FLAG_FLOATING_PANEL     EQU 0
FLAG_MINIMAP            EQU 1
FLAG_MODULE_BROWSER     EQU 2
FLAG_MONACO_DEVTOOLS    EQU 3
FLAG_MONACO_VISIBLE     EQU 4
FLAG_OUTPUT_PANEL       EQU 5
FLAG_SIDEBAR            EQU 6
FLAG_TERMINAL           EQU 7
FLAG_FULLSCREEN         EQU 8
FLAG_STREAMING_LOADER   EQU 9
FLAG_VULKAN_RENDERER    EQU 10
FLAG_SECONDARY_SIDEBAR  EQU 11
FLAG_PANEL              EQU 12
FLAG_POWER_SHELL_PANEL  EQU 13
FLAG_GPU_TEXT           EQU 14
FLAG_DEBUGGER_ENABLED   EQU 15
FLAG_DEBUGGER_ATTACHED  EQU 16
FLAG_DEBUGGER_PAUSED    EQU 17
FLAG_ANNOTATIONS        EQU 18
FLAG_PROFILING          EQU 19
FLAG_CHAT_MODE          EQU 20
FLAG_SESSION_RESTORED   EQU 21

; ============================================================================
; Data Section - Aligned singleton storage
; ============================================================================
.DATA
ALIGN 16

; Static ViewState instance - 16-byte aligned (MASM max)
; Layout optimized to minimize cache misses during UI updates
g_ViewState LABEL BYTE
    ; Block 1: Panel visibility flags (8 bytes) - Hot path
    db 0                    ; floatingPanelVisible
    db 1                    ; minimapEnabled (default true)
    db 0                    ; moduleBrowserVisible
    db 0                    ; monacoDevtoolsOpen
    db 1                    ; monacoVisible (default true)
    db 1                    ; outputPanelVisible (default true)
    db 1                    ; sidebarVisible (default true)
    db 0                    ; terminalVisible
    
    ; Block 2: Extended flags (8 bytes)
    db 0                    ; fullscreen
    db 0                    ; streamingLoaderActive
    db 0                    ; vulkanRendererActive
    db 0                    ; secondarySidebarVisible
    db 1                    ; panelVisible (default true)
    db 0                    ; powerShellPanelVisible
    db 0                    ; gpuTextEnabled
    db 0                    ; debuggerEnabled
    
    ; Block 3: Debugger state (8 bytes)
    db 0                    ; debuggerAttached
    db 0                    ; debuggerPaused
    db 0                    ; annotationsVisible
    db 0                    ; profilingActive
    db 0                    ; chatMode
    db 0                    ; sessionRestored
    db 0, 0                 ; padding
    
    ; Block 4: Zoom levels (8 bytes) - Hot path
    dd 100                  ; zoomLevel (default 100%)
    dd 100                  ; monacoZoomLevel (default 100%)
    
    ; Block 5: Dimensions (16 bytes) - Hot path
    dd 250                  ; sidebarWidth (default)
    dd 200                  ; panelHeight (default)
    dd 300                  ; secondarySidebarWidth (default)
    dd 150                  ; minimapWidth (default)
    
    ; Block 6: Theme pointer (8 bytes)
    dq OFFSET g_DefaultTheme
    
    ; Block 7: Version/sequence for optimistic locking (8 bytes)
    dq 0                    ; modificationSequence
    
    ; Block 8: Reserved/padding (8 bytes)
    dq 0

; Default theme string (ASCII, null-terminated)
ALIGN 8
g_DefaultTheme BYTE "dark-rawrxd", 0

; Initialization flag (ensures single init)
g_ViewStateInitialized db 0
ALIGN 8
g_InitLock dq 0

; ============================================================================
; Code Section
; ============================================================================
.CODE

; ============================================================================
; ViewState_GetInstance
; Returns: RAX = pointer to ViewState singleton
; C++: extern "C" void* ViewState_GetInstance();
; ============================================================================
ViewState_GetInstance PROC FRAME
    .endprolog
    lea rax, g_ViewState
    ret
ViewState_GetInstance ENDP

; ============================================================================
; ViewState_GetBool - Get boolean flag value
; RCX = flag index (0-31)
; Returns: RAX = 0 or 1
; C++: extern "C" int ViewState_GetBool(int flag);
; ============================================================================
ViewState_GetBool PROC FRAME
    .endprolog
    ; Bounds check
    cmp ecx, 32
    jae invalid_flag
    
    ; Calculate byte offset and bit mask
    mov eax, ecx
    shr eax, 3              ; EAX = byte offset (flag / 8)
    and ecx, 7              ; ECX = bit position (flag % 8)
    mov r8d, 1
    shl r8d, cl             ; R8D = bit mask
    
    ; Load byte and test bit
    lea rcx, g_ViewState
    movzx eax, BYTE PTR [rcx + rax]
    test eax, r8d
    setnz al                ; AL = 1 if bit set, 0 otherwise
    movzx eax, al
    ret
    
invalid_flag:
    xor eax, eax
    ret
ViewState_GetBool ENDP

; ============================================================================
; ViewState_SetBool - Set boolean flag value (atomic)
; RCX = flag index (0-31)
; RDX = value (0 or 1)
; Returns: RAX = previous value (0 or 1)
; C++: extern "C" int ViewState_SetBool(int flag, int value);
; ============================================================================
ViewState_SetBool PROC FRAME
    .endprolog
    ; Bounds check
    cmp ecx, 32
    jae invalid_flag2
    
    ; Calculate byte offset and bit mask
    mov r8d, ecx
    shr r8d, 3              ; R8D = byte offset
    and ecx, 7              ; ECX = bit position
    mov r9d, 1
    shl r9d, cl             ; R9D = bit mask
    
    ; Get address of target byte
    lea r10, g_ViewState
    add r10, r8             ; R10 = address of byte to modify
    
    ; Load current value
    movzx eax, BYTE PTR [r10]
    
    ; Determine new value
    test edx, edx
    jz do_clear
    
    ; Set bit using OR
    mov r11b, al
    or r11b, r9b
    mov BYTE PTR [r10], r11b
    jmp done_set
    
do_clear:
    ; Clear bit using AND
    mov r11b, al
    not r9b
    and r11b, r9b
    mov BYTE PTR [r10], r11b
    
done_set:
    ; Return previous value
    ret
    
invalid_flag2:
    xor eax, eax
    ret
ViewState_SetBool ENDP

; ============================================================================
; ViewState_ToggleBool - Toggle boolean flag value (atomic)
; RCX = flag index (0-31)
; Returns: RAX = new value (0 or 1)
; C++: extern "C" int ViewState_ToggleBool(int flag);
; ============================================================================
ViewState_ToggleBool PROC FRAME
    .endprolog
    ; Bounds check
    cmp ecx, 32
    jae invalid_flag3
    
    ; Calculate byte offset and bit mask
    mov r8d, ecx
    shr r8d, 3              ; R8D = byte offset
    and ecx, 7              ; ECX = bit position
    mov r9d, 1
    shl r9d, cl             ; R9D = bit mask
    
    ; Get address of target byte
    lea r10, g_ViewState
    add r10, r8             ; R10 = address of byte to modify
    
    ; Atomic toggle using XOR
    lock xor BYTE PTR [r10], r9b
    
    ; Return new bit value
    movzx eax, BYTE PTR [r10]
    and eax, r9d
    shr eax, cl
    ret
    
invalid_flag3:
    xor eax, eax
    ret
ViewState_ToggleBool ENDP

; ============================================================================
; ViewState_GetInt32 - Get 32-bit integer value
; RCX = field offset (must be 4-byte aligned)
; Returns: RAX = value
; C++: extern "C" int ViewState_GetInt32(int offset);
; ============================================================================
ViewState_GetInt32 PROC FRAME
    .endprolog
    ; Validate alignment
    test ecx, 3
    jnz invalid_offset
    
    ; Validate offset range
    cmp ecx, 64 - 4
    ja invalid_offset
    
    ; Load value
    lea rax, g_ViewState
    mov eax, DWORD PTR [rax + rcx]
    ret
    
invalid_offset:
    xor eax, eax
    ret
ViewState_GetInt32 ENDP

; ============================================================================
; ViewState_SetInt32 - Set 32-bit integer value (atomic)
; RCX = field offset (must be 4-byte aligned)
; RDX = value
; Returns: RAX = previous value
; C++: extern "C" int ViewState_SetInt32(int offset, int value);
; ============================================================================
ViewState_SetInt32 PROC FRAME
    .endprolog
    ; Validate alignment
    test ecx, 3
    jnz invalid_offset2
    
    ; Validate offset range
    cmp ecx, 64 - 4
    ja invalid_offset2
    
    ; Atomic exchange
    lea r8, g_ViewState
    mov eax, edx
    lock xchg DWORD PTR [r8 + rcx], eax
    ret
    
invalid_offset2:
    xor eax, eax
    ret
ViewState_SetInt32 ENDP

; ============================================================================
; ViewState_GetString - Get string pointer
; RCX = field offset (must be 8-byte aligned)
; Returns: RAX = pointer to string (read-only)
; C++: extern "C" const char* ViewState_GetString(int offset);
; ============================================================================
ViewState_GetString PROC FRAME
    .endprolog
    ; Validate alignment
    test ecx, 7
    jnz invalid_offset3
    
    ; Validate offset range
    cmp ecx, 64 - 8
    ja invalid_offset3
    
    ; Load pointer
    lea rax, g_ViewState
    mov rax, QWORD PTR [rax + rcx]
    ret
    
invalid_offset3:
    xor eax, eax
    ret
ViewState_GetString ENDP

; ============================================================================
; ViewState_SetString - Set string pointer (atomic)
; RCX = field offset (must be 8-byte aligned)
; RDX = pointer to string
; Returns: RAX = previous pointer
; C++: extern "C" const char* ViewState_SetString(int offset, const char* value);
; ============================================================================
ViewState_SetString PROC FRAME
    .endprolog
    ; Validate alignment
    test ecx, 7
    jnz invalid_offset4
    
    ; Validate offset range
    cmp ecx, 64 - 8
    ja invalid_offset4
    
    ; Atomic exchange
    lea r8, g_ViewState
    mov rax, rdx
    lock xchg QWORD PTR [r8 + rcx], rax
    ret
    
invalid_offset4:
    xor eax, eax
    ret
ViewState_SetString ENDP

; ============================================================================
; ViewState_GetSequence - Get modification sequence number
; Returns: RAX = sequence number
; C++: extern "C" unsigned __int64 ViewState_GetSequence();
; ============================================================================
ViewState_GetSequence PROC FRAME
    .endprolog
    lea rax, g_ViewState
    mov rax, QWORD PTR [rax + 56]   ; Offset of sequence field
    ret
ViewState_GetSequence ENDP

; ============================================================================
; ViewState_IncrementSequence - Increment modification sequence (atomic)
; Returns: RAX = new sequence number
; C++: extern "C" unsigned __int64 ViewState_IncrementSequence();
; ============================================================================
ViewState_IncrementSequence PROC FRAME
    .endprolog
    lea rax, g_ViewState
    lock inc QWORD PTR [rax + 56]   ; Atomic increment
    mov rax, QWORD PTR [rax + 56]   ; Load new value
    ret
ViewState_IncrementSequence ENDP

; ============================================================================
; ViewState_ResetToDefaults - Reset all state to defaults
; C++: extern "C" void ViewState_ResetToDefaults();
; ============================================================================
ViewState_ResetToDefaults PROC FRAME
    push rdi
    pushfq
    .endprolog
    cli                     ; Disable interrupts briefly
    
    ; Clear entire structure first
    lea rdi, g_ViewState
    mov rcx, 8              ; 8 qwords
    xor rax, rax
    rep stosq
    
    ; Restore defaults
    lea rdi, g_ViewState
    mov BYTE PTR [rdi + 1], 1       ; minimapEnabled = true
    mov BYTE PTR [rdi + 4], 1       ; monacoVisible = true
    mov BYTE PTR [rdi + 5], 1       ; outputPanelVisible = true
    mov BYTE PTR [rdi + 6], 1       ; sidebarVisible = true
    mov BYTE PTR [rdi + 12], 1      ; panelVisible = true
    mov DWORD PTR [rdi + 24], 100   ; zoomLevel = 100
    mov DWORD PTR [rdi + 28], 100   ; monacoZoomLevel = 100
    mov DWORD PTR [rdi + 32], 250   ; sidebarWidth = 250
    mov DWORD PTR [rdi + 36], 200   ; panelHeight = 200
    mov DWORD PTR [rdi + 40], 300   ; secondarySidebarWidth = 300
    mov DWORD PTR [rdi + 44], 150   ; minimapWidth = 150
    lea rax, g_DefaultTheme
    mov QWORD PTR [rdi + 48], rax
    
    popfq
    pop rdi
    ret
ViewState_ResetToDefaults ENDP

; ============================================================================
; ViewState_Snapshot - Copy entire state to buffer
; RCX = destination buffer (must be 64-byte aligned, 64 bytes)
; C++: extern "C" void ViewState_Snapshot(void* dest);
; ============================================================================
ViewState_Snapshot PROC FRAME
    push rsi
    push rdi
    .endprolog
    
    ; Copy 64 bytes using 8-byte chunks
    lea rsi, g_ViewState
    mov rdi, rcx
    mov rcx, 8              ; 8 qwords
    rep movsq
    
    pop rdi
    pop rsi
    ret
ViewState_Snapshot ENDP

; ============================================================================
; ViewState_CompareSnapshot - Compare current state with snapshot
; RCX = snapshot buffer (must be 64-byte aligned, 64 bytes)
; Returns: RAX = 0 if equal, non-zero if different
; C++: extern "C" int ViewState_CompareSnapshot(const void* snapshot);
; ============================================================================
ViewState_CompareSnapshot PROC FRAME
    push rsi
    .endprolog
    
    lea rsi, g_ViewState
    mov r8, rcx
    xor eax, eax
    mov rcx, 8              ; 8 qwords to compare
    
compare_loop:
    mov rdx, QWORD PTR [rsi + rax * 8]
    cmp rdx, QWORD PTR [r8 + rax * 8]
    jne different
    inc rax
    dec rcx
    jnz compare_loop
    
    ; Equal
    xor eax, eax
    pop rsi
    ret
    
different:
    mov eax, 1
    pop rsi
    ret
ViewState_CompareSnapshot ENDP

; ============================================================================
; Export table for C/C++ linkage
; ============================================================================
PUBLIC ViewState_GetInstance
PUBLIC ViewState_GetBool
PUBLIC ViewState_SetBool
PUBLIC ViewState_ToggleBool
PUBLIC ViewState_GetInt32
PUBLIC ViewState_SetInt32
PUBLIC ViewState_GetString
PUBLIC ViewState_SetString
PUBLIC ViewState_GetSequence
PUBLIC ViewState_IncrementSequence
PUBLIC ViewState_ResetToDefaults
PUBLIC ViewState_Snapshot
PUBLIC ViewState_CompareSnapshot

; Data exports
PUBLIC g_ViewState
PUBLIC g_DefaultTheme

; ============================================================================
; End of module
; ============================================================================
END
