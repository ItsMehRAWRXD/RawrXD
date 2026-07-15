; =============================================================================
; plugin_host.asm - Plugin Host Integration Example
; =============================================================================
; Demonstrates how win32ide_main.asm loads and uses plugin DLLs via VTable.
; This is the "Plugin Host" pattern that eliminates GetProcAddress boilerplate.
;
; Architecture:
;   1. LoadLibrary("editor_pipeline.dll")
;   2. GetProcAddress(hModule, "GetVTable")
;   3. call GetVTable -> returns &g_EditorVTable
;   4. mov rbx, rax; call [rbx].EDITOR_PIPELINE_VTABLE.pfnInit
;
; Benefits:
;   - Single GetProcAddress call per DLL (not per function)
;   - O(1) function lookup via structure displacement
;   - Clean ABI boundary between host and plugins
;   - Easy to test plugins in isolation
;
; Version: 1.0
; Date: 2026-06-18
; =============================================================================

option casemap:none

; Include interface definitions
include plugin_iface.inc

; =============================================================================
; Data Structures
; =============================================================================

; Plugin module info
PLUGIN_MODULE STRUCT
    hModule         QWORD ?         ; HMODULE from LoadLibrary
    pVTable         QWORD ?         ; Pointer to vtable
    pModuleName     QWORD ?         ; Module name string
PLUGIN_MODULE ENDS

; =============================================================================
; .data Section
; =============================================================================

.data

; Plugin DLL names
szEditorDLL      BYTE "editor_pipeline.dll", 0
szDebugDLL       BYTE "debug_pipeline.dll", 0
szSyntaxDLL      BYTE "syntax_pipeline.dll", 0

; VTable function name (same for all plugins)
szGetVTable      BYTE "GetVTable", 0

; Plugin modules
g_EditorModule   PLUGIN_MODULE <>
g_DebugModule    PLUGIN_MODULE <>
g_SyntaxModule   PLUGIN_MODULE <>

; Initialization flags
g_bEditorLoaded   DWORD FALSE
g_bDebugLoaded    DWORD FALSE
g_bSyntaxLoaded   DWORD FALSE

; Error messages
szLoadFailed     BYTE "Failed to load plugin", 13, 10, 0
szVTableFailed   BYTE "Failed to get VTable", 13, 10, 0
szInitFailed     BYTE "Plugin initialization failed", 13, 10, 0

; =============================================================================
; .code Section
; =============================================================================

.code

; -----------------------------------------------------------------------------
; Plugin_LoadEditor - Load editor pipeline plugin
; -----------------------------------------------------------------------------
; Returns: RAX = TRUE on success, FALSE on failure
; -----------------------------------------------------------------------------
Plugin_LoadEditor PROC PUBLIC
    push rbx
    push rsi
    
    ; Check if already loaded
    mov eax, g_bEditorLoaded
    test eax, eax
    jnz load_success
    
    ; Load DLL
    lea rcx, szEditorDLL
    call LoadLibraryA
    test rax, rax
    jz load_failed
    
    ; Store module handle
    mov g_EditorModule.hModule, rax
    mov rbx, rax
    
    ; Get VTable
    lea rdx, szGetVTable
    call GetProcAddress
    test rax, rax
    jz vtable_failed
    
    ; Call GetVTable
    call rax
    
    ; Store VTable pointer
    mov g_EditorModule.pVTable, rax
    
    ; Initialize plugin
    mov rbx, rax
    call [rbx].EDITOR_PIPELINE_VTABLE.pfnInit
    test eax, eax
    jz init_failed
    
    ; Mark as loaded
    mov g_bEditorLoaded, TRUE
    
load_success:
    mov eax, TRUE
    jmp load_done
    
load_failed:
    lea rcx, szLoadFailed
    call OutputDebugStringA
    xor eax, eax
    jmp load_done
    
vtable_failed:
    lea rcx, szVTableFailed
    call OutputDebugStringA
    xor eax, eax
    jmp load_done
    
init_failed:
    lea rcx, szInitFailed
    call OutputDebugStringA
    xor eax, eax
    
load_done:
    pop rsi
    pop rbx
    ret
Plugin_LoadEditor ENDP

; -----------------------------------------------------------------------------
; Plugin_LoadDebug - Load debug pipeline plugin
; -----------------------------------------------------------------------------
; Returns: RAX = TRUE on success, FALSE on failure
; -----------------------------------------------------------------------------
Plugin_LoadDebug PROC PUBLIC
    push rbx
    push rsi
    
    ; Check if already loaded
    mov eax, g_bDebugLoaded
    test eax, eax
    jnz load_success
    
    ; Load DLL
    lea rcx, szDebugDLL
    call LoadLibraryA
    test rax, rax
    jz load_failed
    
    ; Store module handle
    mov g_DebugModule.hModule, rax
    mov rbx, rax
    
    ; Get VTable
    lea rdx, szGetVTable
    call GetProcAddress
    test rax, rax
    jz vtable_failed
    
    ; Call GetVTable
    call rax
    
    ; Store VTable pointer
    mov g_DebugModule.pVTable, rax
    
    ; Initialize plugin
    mov rbx, rax
    call [rbx].DEBUG_PIPELINE_VTABLE.pfnInit
    test eax, eax
    jz init_failed
    
    ; Mark as loaded
    mov g_bDebugLoaded, TRUE
    
load_success:
    mov eax, TRUE
    jmp load_done
    
load_failed:
    lea rcx, szLoadFailed
    call OutputDebugStringA
    xor eax, eax
    jmp load_done
    
vtable_failed:
    lea rcx, szVTableFailed
    call OutputDebugStringA
    xor eax, eax
    jmp load_done
    
init_failed:
    lea rcx, szInitFailed
    call OutputDebugStringA
    xor eax, eax
    
load_done:
    pop rsi
    pop rbx
    ret
Plugin_LoadDebug ENDP

; -----------------------------------------------------------------------------
; Plugin_LoadSyntax - Load syntax highlighter plugin
; -----------------------------------------------------------------------------
; Returns: RAX = TRUE on success, FALSE on failure
; -----------------------------------------------------------------------------
Plugin_LoadSyntax PROC PUBLIC
    push rbx
    push rsi
    
    ; Check if already loaded
    mov eax, g_bSyntaxLoaded
    test eax, eax
    jnz load_success
    
    ; Load DLL
    lea rcx, szSyntaxDLL
    call LoadLibraryA
    test rax, rax
    jz load_failed
    
    ; Store module handle
    mov g_SyntaxModule.hModule, rax
    mov rbx, rax
    
    ; Get VTable
    lea rdx, szGetVTable
    call GetProcAddress
    test rax, rax
    jz vtable_failed
    
    ; Call GetVTable
    call rax
    
    ; Store VTable pointer
    mov g_SyntaxModule.pVTable, rax
    
    ; Initialize plugin
    mov rbx, rax
    call [rbx].SYNTAX_HIGHLIGHTER_VTABLE.pfnInit
    test eax, eax
    jz init_failed
    
    ; Mark as loaded
    mov g_bSyntaxLoaded, TRUE
    
load_success:
    mov eax, TRUE
    jmp load_done
    
load_failed:
    lea rcx, szLoadFailed
    call OutputDebugStringA
    xor eax, eax
    jmp load_done
    
vtable_failed:
    lea rcx, szVTableFailed
    call OutputDebugStringA
    xor eax, eax
    jmp load_done
    
init_failed:
    lea rcx, szInitFailed
    call OutputDebugStringA
    xor eax, eax
    
load_done:
    pop rsi
    pop rbx
    ret
Plugin_LoadSyntax ENDP

; -----------------------------------------------------------------------------
; Plugin_UnloadAll - Unload all plugins
; -----------------------------------------------------------------------------
Plugin_UnloadAll PROC PUBLIC
    ; Unload syntax highlighter
    mov eax, g_bSyntaxLoaded
    test eax, eax
    jz skip_syntax
    
    ; Call shutdown
    mov rbx, g_SyntaxModule.pVTable
    test rbx, rbx
    jz skip_syntax_shutdown
    call [rbx].SYNTAX_HIGHLIGHTER_VTABLE.pfnShutdown
    
skip_syntax_shutdown:
    ; Free library
    mov rcx, g_SyntaxModule.hModule
    test rcx, rcx
    jz skip_syntax
    call FreeLibrary
    
skip_syntax:
    mov g_bSyntaxLoaded, FALSE
    mov g_SyntaxModule.hModule, 0
    mov g_SyntaxModule.pVTable, 0
    
    ; Unload debug pipeline
    mov eax, g_bDebugLoaded
    test eax, eax
    jz skip_debug
    
    ; Call shutdown
    mov rbx, g_DebugModule.pVTable
    test rbx, rbx
    jz skip_debug_shutdown
    call [rbx].DEBUG_PIPELINE_VTABLE.pfnShutdown
    
skip_debug_shutdown:
    ; Free library
    mov rcx, g_DebugModule.hModule
    test rcx, rcx
    jz skip_debug
    call FreeLibrary
    
skip_debug:
    mov g_bDebugLoaded, FALSE
    mov g_DebugModule.hModule, 0
    mov g_DebugModule.pVTable, 0
    
    ; Unload editor pipeline
    mov eax, g_bEditorLoaded
    test eax, eax
    jz skip_editor
    
    ; Call shutdown
    mov rbx, g_EditorModule.pVTable
    test rbx, rbx
    jz skip_editor_shutdown
    call [rbx].EDITOR_PIPELINE_VTABLE.pfnShutdown
    
skip_editor_shutdown:
    ; Free library
    mov rcx, g_EditorModule.hModule
    test rcx, rcx
    jz skip_editor
    call FreeLibrary
    
skip_editor:
    mov g_bEditorLoaded, FALSE
    mov g_EditorModule.hModule, 0
    mov g_EditorModule.pVTable, 0
    
    ret
Plugin_UnloadAll ENDP

; =============================================================================
; Example Usage in Main Loop
; =============================================================================

; Example: Handle keyboard input
; This shows how clean the VTable pattern makes the hot path
Example_HandleInput PROC
    ; Assume we have an INPUT_EVENT in rcx
    
    ; Get editor VTable
    mov rbx, g_EditorModule.pVTable
    test rbx, rbx
    jz input_done
    
    ; Push input event (single call, no GetProcAddress)
    ; rcx already contains INPUT_EVENT*
    call [rbx].EDITOR_PIPELINE_VTABLE.pfnPushInput
    
input_done:
    ret
Example_HandleInput ENDP

; Example: Poll debug events during render loop
Example_PollDebugEvents PROC
    ; Get debug VTable
    mov rbx, g_DebugModule.pVTable
    test rbx, rbx
    jz poll_done
    
    ; Poll for events (call during 60 FPS render loop)
    call [rbx].DEBUG_PIPELINE_VTABLE.pfnDebugPoll
    
    ; Check if halted
    call [rbx].DEBUG_PIPELINE_VTABLE.pfnGetState
    test eax, DBG_STATE_HALTED
    jz poll_done
    
    ; Get current line for highlighting
    call [rbx].DEBUG_PIPELINE_VTABLE.pfnGetCurrentLine
    ; eax now contains current line number
    
poll_done:
    ret
Example_PollDebugEvents ENDP

; Example: Scan line for syntax highlighting
Example_ScanLine PROC
    ; Assume:
    ;   ecx = line number
    ;   rdx = pointer to line text (WCHAR*)
    ;   r8d = line length
    
    ; Get syntax VTable
    mov rbx, g_SyntaxModule.pVTable
    test rbx, rbx
    jz scan_done
    
    ; Scan line
    call [rbx].SYNTAX_HIGHLIGHTER_VTABLE.pfnScanLine
    ; eax now contains token count
    
scan_done:
    ret
Example_ScanLine ENDP

; =============================================================================
; External Declarations
; =============================================================================

EXTERN LoadLibraryA:PROC
EXTERN GetProcAddress:PROC
EXTERN FreeLibrary:PROC
EXTERN OutputDebugStringA:PROC

END
