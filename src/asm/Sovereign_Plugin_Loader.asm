; ==============================================================================
; Sovereign_Plugin_Loader.asm
; Sovereign Plugin Manifest & Loading Subsystem
; Implementation of "Elite" Suite Component #5
; ==============================================================================

option casemap:none
include Sovereign_Common.inc

EXTERN g_ApiTable : SOVEREIGN_API_TABLE
EXTERN Sovereign_ResolveExport : PROC

.DATA
    plugin_path     db ".\plugins\*.dll", 0
    plugin_init_fn  db "Sovereign_PluginInit", 0

.CODE

; ------------------------------------------------------------------------------
; PROCEDURE: Sovereign_LoadPlugins
; Input:  None
; Output: None (Iterates and loads found DLLs)
; ------------------------------------------------------------------------------
Sovereign_LoadPlugins PROC
    push rbx
    push rsi
    push rdi
    sub rsp, 624                ; Large enough for WIN32_FIND_DATA (592 bytes) + Align

    lea rcx, plugin_path
    mov rdx, rsp                ; RDX = &WIN32_FIND_DATA
    call [g_ApiTable.pFindFirstFileA]
    
    mov rbx, rax                ; RBX = FindHandle
    cmp rax, -1
    je no_plugins

find_loop:
    ; WIN32_FIND_DATA.cFileName is at offset 44
    lea rcx, [rsp + 44]         ; DLL Name
    call [g_ApiTable.pLoadLibraryA]
    test rax, rax
    jz next_file
    
    mov rsi, rax                ; RSI = Module Handle
    
    ; Resolve PluginInit
    mov rcx, rax
    lea rdx, plugin_init_fn
    call Sovereign_ResolveExport
    test rax, rax
    jz next_file
    
    ; Call PluginInit(ApiTablePtr)
    lea rcx, g_ApiTable
    call rax
    
next_file:
    mov rcx, rbx                ; Handle
    mov rdx, rsp                ; &WIN32_FIND_DATA
    call [g_ApiTable.pFindNextFileA]
    test rax, rax
    jnz find_loop

    mov rcx, rbx
    call [g_ApiTable.pFindClose]

no_plugins:
    add rsp, 624
    pop rdi
    pop rsi
    pop rbx
    ret
Sovereign_LoadPlugins ENDP

END
