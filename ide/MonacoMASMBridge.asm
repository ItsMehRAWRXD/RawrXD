; ==============================================================================
; MonacoMASMBridge.asm - Bridge between C++ and Pure MASM64 Monaco Editor
; ==============================================================================
; This file provides the glue layer between the C++ MonacoEditorPanel and
; the pure MASM64 Monaco editor implementation (MONACO_EDITOR_ENTERPRISE.ASM)
; ==============================================================================

OPTION CASEMAP:NONE
OPTION WIN64:3

; ==============================================================================
; INCLUDES
; ==============================================================================
INCLUDE \masm64\include64\masm64rt.inc
INCLUDE \rawrxd\include\rawrxd_master.inc

; ==============================================================================
; DATA SECTION
; ==============================================================================
.DATA

; Editor instance pointer (singleton for now)
g_pMASMEditor       QWORD   0

; Function pointers to MASM Monaco implementation
; These would be linked from MONACO_EDITOR_ENTERPRISE.ASM
EXTERN EnterpriseEditorCreate:PROC
EXTERN EnterpriseEditorDestroy:PROC
EXTERN EnterpriseEditorLoadFile:PROC
EXTERN EnterpriseEditorSaveFile:PROC
EXTERN EnterpriseEditorShowGhostText:PROC
EXTERN EnterpriseEditorHideGhostText:PROC
EXTERN EnterpriseEditorAcceptGhostText:PROC
EXTERN EnterpriseEditorRequestCompletion:PROC
EXTERN EnterpriseEditorSetTheme:PROC
EXTERN EnterpriseEditorEnableLSP:PROC
EXTERN EnterpriseEditorEnableIntelliSense:PROC
EXTERN EnterpriseEditorEnableGhostText:PROC
EXTERN EnterpriseEditorSetEnterpriseMode:PROC
EXTERN EnterpriseEditorSetAuditMode:PROC
EXTERN EnterpriseEditorSetSecureMode:PROC
EXTERN EnterpriseEditorIsReady:PROC

; ==============================================================================
; CODE SECTION
; ==============================================================================
.CODE

; ==============================================================================
; PUBLIC EXPORTS (for C++ linkage)
; ==============================================================================

PUBLIC MASMMonaco_CreateEditor
PUBLIC MASMMonaco_DestroyEditor
PUBLIC MASMMonaco_LoadFile
PUBLIC MASMMonaco_SaveFile
PUBLIC MASMMonaco_ShowGhostText
PUBLIC MASMMonaco_HideGhostText
PUBLIC MASMMonaco_AcceptGhostText
PUBLIC MASMMonaco_RequestCompletion
PUBLIC MASMMonaco_SetTheme
PUBLIC MASMMonaco_EnableLSP
PUBLIC MASMMonaco_EnableIntelliSense
PUBLIC MASMMonaco_EnableGhostText
PUBLIC MASMMonaco_SetEnterpriseMode
PUBLIC MASMMonaco_SetAuditMode
PUBLIC MASMMonaco_SetSecureMode
PUBLIC MASMMonaco_IsReady

; ==============================================================================
; MASMMonaco_CreateEditor
; RCX = HWND (parent window handle)
; Returns: RAX = editor instance pointer
; ==============================================================================
MASMMonaco_CreateEditor PROC FRAME
    push    rbx
    push    rsi
    push    rdi
    push    r12
    .allocstack 32
    .endprolog
    
    mov     rbx, rcx                    ; Save HWND
    
    ; Call EnterpriseEditorCreate from MONACO_EDITOR_ENTERPRISE.ASM
    ; RCX = workspace root path (NULL for now)
    xor     rcx, rcx
    call    EnterpriseEditorCreate
    
    ; Store the editor pointer
    mov     g_pMASMEditor, rax
    
    ; Return the editor pointer
    mov     rax, g_pMASMEditor
    
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
MASMMonaco_CreateEditor ENDP

; ==============================================================================
; MASMMonaco_DestroyEditor
; RCX = editor instance pointer
; ==============================================================================
MASMMonaco_DestroyEditor PROC FRAME
    push    rbx
    .allocstack 8
    .endprolog
    
    mov     rbx, rcx                    ; Editor pointer
    
    ; Call EnterpriseEditorDestroy
    mov     rcx, rbx
    call    EnterpriseEditorDestroy
    
    mov     g_pMASMEditor, 0
    
    pop     rbx
    ret
MASMMonaco_DestroyEditor ENDP

; ==============================================================================
; MASMMonaco_LoadFile
; RCX = editor instance pointer
; RDX = file path (const char*)
; ==============================================================================
MASMMonaco_LoadFile PROC FRAME
    push    rbx
    push    rsi
    .allocstack 16
    .endprolog
    
    mov     rbx, rcx                    ; Editor pointer
    mov     rsi, rdx                    ; File path
    
    ; Convert ASCII path to Unicode if needed
    ; For now, assume the MASM implementation handles it
    
    ; Call EnterpriseEditorLoadFile
    mov     rcx, rbx
    mov     rdx, rsi
    call    EnterpriseEditorLoadFile
    
    pop     rsi
    pop     rbx
    ret
MASMMonaco_LoadFile ENDP

; ==============================================================================
; MASMMonaco_SaveFile
; RCX = editor instance pointer
; ==============================================================================
MASMMonaco_SaveFile PROC FRAME
    push    rbx
    .allocstack 8
    .endprolog
    
    mov     rbx, rcx                    ; Editor pointer
    
    ; Call EnterpriseEditorSaveFile
    mov     rcx, rbx
    call    EnterpriseEditorSaveFile
    
    pop     rbx
    ret
MASMMonaco_SaveFile ENDP

; ==============================================================================
; MASMMonaco_ShowGhostText
; RCX = editor instance pointer
; RDX = text (const wchar_t*)
; ==============================================================================
MASMMonaco_ShowGhostText PROC FRAME
    push    rbx
    push    rsi
    .allocstack 16
    .endprolog
    
    mov     rbx, rcx                    ; Editor pointer
    mov     rsi, rdx                    ; Text
    
    ; Call EnterpriseEditorShowGhostText
    mov     rcx, rbx
    mov     rdx, rsi
    call    EnterpriseEditorShowGhostText
    
    pop     rsi
    pop     rbx
    ret
MASMMonaco_ShowGhostText ENDP

; ==============================================================================
; MASMMonaco_HideGhostText
; RCX = editor instance pointer
; ==============================================================================
MASMMonaco_HideGhostText PROC FRAME
    push    rbx
    .allocstack 8
    .endprolog
    
    mov     rbx, rcx                    ; Editor pointer
    
    ; Call EnterpriseEditorHideGhostText
    mov     rcx, rbx
    call    EnterpriseEditorHideGhostText
    
    pop     rbx
    ret
MASMMonaco_HideGhostText ENDP

; ==============================================================================
; MASMMonaco_AcceptGhostText
; RCX = editor instance pointer
; ==============================================================================
MASMMonaco_AcceptGhostText PROC FRAME
    push    rbx
    .allocstack 8
    .endprolog
    
    mov     rbx, rcx                    ; Editor pointer
    
    ; Call EnterpriseEditorAcceptGhostText
    mov     rcx, rbx
    call    EnterpriseEditorAcceptGhostText
    
    pop     rbx
    ret
MASMMonaco_AcceptGhostText ENDP

; ==============================================================================
; MASMMonaco_RequestCompletion
; RCX = editor instance pointer
; ==============================================================================
MASMMonaco_RequestCompletion PROC FRAME
    push    rbx
    .allocstack 8
    .endprolog
    
    mov     rbx, rcx                    ; Editor pointer
    
    ; Call EnterpriseEditorRequestCompletion
    mov     rcx, rbx
    call    EnterpriseEditorRequestCompletion
    
    pop     rbx
    ret
MASMMonaco_RequestCompletion ENDP

; ==============================================================================
; MASMMonaco_SetTheme
; RCX = editor instance pointer
; RDX = theme ID (0=dark, 1=light, etc.)
; ==============================================================================
MASMMonaco_SetTheme PROC FRAME
    push    rbx
    push    rsi
    .allocstack 16
    .endprolog
    
    mov     rbx, rcx                    ; Editor pointer
    mov     rsi, rdx                    ; Theme ID
    
    ; Call EnterpriseEditorSetTheme
    mov     rcx, rbx
    mov     rdx, rsi
    call    EnterpriseEditorSetTheme
    
    pop     rsi
    pop     rbx
    ret
MASMMonaco_SetTheme ENDP

; ==============================================================================
; MASMMonaco_EnableLSP
; RCX = editor instance pointer
; RDX = enable (bool)
; ==============================================================================
MASMMonaco_EnableLSP PROC FRAME
    push    rbx
    push    rsi
    .allocstack 16
    .endprolog
    
    mov     rbx, rcx                    ; Editor pointer
    mov     rsi, rdx                    ; Enable flag
    
    ; Call EnterpriseEditorEnableLSP
    mov     rcx, rbx
    mov     rdx, rsi
    call    EnterpriseEditorEnableLSP
    
    pop     rsi
    pop     rbx
    ret
MASMMonaco_EnableLSP ENDP

; ==============================================================================
; MASMMonaco_EnableIntelliSense
; RCX = editor instance pointer
; RDX = enable (bool)
; ==============================================================================
MASMMonaco_EnableIntelliSense PROC FRAME
    push    rbx
    push    rsi
    .allocstack 16
    .endprolog
    
    mov     rbx, rcx                    ; Editor pointer
    mov     rsi, rdx                    ; Enable flag
    
    ; Call EnterpriseEditorEnableIntelliSense
    mov     rcx, rbx
    mov     rdx, rsi
    call    EnterpriseEditorEnableIntelliSense
    
    pop     rsi
    pop     rbx
    ret
MASMMonaco_EnableIntelliSense ENDP

; ==============================================================================
; MASMMonaco_EnableGhostText
; RCX = editor instance pointer
; RDX = enable (bool)
; ==============================================================================
MASMMonaco_EnableGhostText PROC FRAME
    push    rbx
    push    rsi
    .allocstack 16
    .endprolog
    
    mov     rbx, rcx                    ; Editor pointer
    mov     rsi, rdx                    ; Enable flag
    
    ; Call EnterpriseEditorEnableGhostText
    mov     rcx, rbx
    mov     rdx, rsi
    call    EnterpriseEditorEnableGhostText
    
    pop     rsi
    pop     rbx
    ret
MASMMonaco_EnableGhostText ENDP

; ==============================================================================
; MASMMonaco_SetEnterpriseMode
; RCX = editor instance pointer
; RDX = enable (bool)
; ==============================================================================
MASMMonaco_SetEnterpriseMode PROC FRAME
    push    rbx
    push    rsi
    .allocstack 16
    .endprolog
    
    mov     rbx, rcx                    ; Editor pointer
    mov     rsi, rdx                    ; Enable flag
    
    ; Call EnterpriseEditorSetEnterpriseMode
    mov     rcx, rbx
    mov     rdx, rsi
    call    EnterpriseEditorSetEnterpriseMode
    
    pop     rsi
    pop     rbx
    ret
MASMMonaco_SetEnterpriseMode ENDP

; ==============================================================================
; MASMMonaco_SetAuditMode
; RCX = editor instance pointer
; RDX = enable (bool)
; ==============================================================================
MASMMonaco_SetAuditMode PROC FRAME
    push    rbx
    push    rsi
    .allocstack 16
    .endprolog
    
    mov     rbx, rcx                    ; Editor pointer
    mov     rsi, rdx                    ; Enable flag
    
    ; Call EnterpriseEditorSetAuditMode
    mov     rcx, rbx
    mov     rdx, rsi
    call    EnterpriseEditorSetAuditMode
    
    pop     rsi
    pop     rbx
    ret
MASMMonaco_SetAuditMode ENDP

; ==============================================================================
; MASMMonaco_SetSecureMode
; RCX = editor instance pointer
; RDX = enable (bool)
; ==============================================================================
MASMMonaco_SetSecureMode PROC FRAME
    push    rbx
    push    rsi
    .allocstack 16
    .endprolog
    
    mov     rbx, rcx                    ; Editor pointer
    mov     rsi, rdx                    ; Enable flag
    
    ; Call EnterpriseEditorSetSecureMode
    mov     rcx, rbx
    mov     rdx, rsi
    call    EnterpriseEditorSetSecureMode
    
    pop     rsi
    pop     rbx
    ret
MASMMonaco_SetSecureMode ENDP

; ==============================================================================
; MASMMonaco_IsReady
; RCX = editor instance pointer
; Returns: RAX = bool (true if ready)
; ==============================================================================
MASMMonaco_IsReady PROC FRAME
    push    rbx
    .allocstack 8
    .endprolog
    
    mov     rbx, rcx                    ; Editor pointer
    
    ; Call EnterpriseEditorIsReady
    mov     rcx, rbx
    call    EnterpriseEditorIsReady
    
    pop     rbx
    ret
MASMMonaco_IsReady ENDP

; ==============================================================================
; END OF MODULE
; ==============================================================================
END
