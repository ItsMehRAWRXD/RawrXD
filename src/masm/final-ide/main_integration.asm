;==============================================================================
; main_integration.asm - Connect Pane System with Existing UI
;==============================================================================

option casemap:none
include windows.inc

PUBLIC InitializeIntegratedIDE, ProcessPaneMessage, UpdateAllPanes

; External references to existing UI system
EXTERN gui_init_registry:PROC
EXTERN ide_init_all_components:PROC
EXTERN ui_create_editor:PROC
EXTERN ui_create_terminal:PROC
EXTERN ui_create_chat:PROC

; External references to new pane system
EXTERN DragPane_Init:PROC
EXTERN pane_message_bus:PROC
EXTERN integrate_with_main:PROC

.code

;==============================================================================
; InitializeIntegratedIDE - Main initialization function
;==============================================================================
InitializeIntegratedIDE PROC
    push rbx
    
    ; Initialize existing GUI system
    call gui_init_registry
    test eax, eax
    jz init_fail
    
    ; Initialize IDE components
    call ide_init_all_components
    test eax, eax
    jz init_fail
    
    ; Initialize drag & drop pane system
    call DragPane_Init
    test eax, eax
    jz init_fail
    
    ; Integrate ASM features with panes
    call integrate_with_main
    test eax, eax
    jz init_fail
    
    ; Create enhanced panes with ASM features
    call CreateEnhancedPanes
    
    mov eax, 1
    jmp init_done
    
init_fail:
    xor eax, eax
    
init_done:
    pop rbx

InitializeIntegratedIDE ENDP

;==============================================================================
; CreateEnhancedPanes - Create panes with embedded ASM features
;==============================================================================
CreateEnhancedPanes PROC
    push rbx
    
    ; Create editor pane with ASM syntax highlighting
    call ui_create_editor
    mov rbx, rax
    test rbx, rbx
    jz create_fail
    
    ; Embed ASM syntax handler
    mov rcx, rbx
    lea rdx, asm_syntax_handler
    call EmbedAsmFeature
    
    ; Create terminal pane with ASM debugging
    call ui_create_terminal
    mov rbx, rax
    test rbx, rbx
    jz create_fail
    
    ; Embed ASM debug handler
    mov rcx, rbx
    lea rdx, asm_debug_handler
    call EmbedAsmFeature
    
    ; Create chat pane with ASM assistance
    call ui_create_chat
    mov rbx, rax
    test rbx, rbx
    jz create_fail
    
    ; Embed ASM chat handler
    mov rcx, rbx
    lea rdx, asm_chat_handler
    call EmbedAsmFeature
    
    mov eax, 1
    jmp create_done
    
create_fail:
    xor eax, eax
    
create_done:
    pop rbx

CreateEnhancedPanes ENDP

;==============================================================================
; ProcessPaneMessage - Handle messages between panes
;==============================================================================
ProcessPaneMessage PROC
    ; rcx = message type, rdx = source pane, r8 = data
    push rbx
    
    ; Route through message bus
    call pane_message_bus
    
    ; Update affected panes
    call UpdateAllPanes
    
    pop ENDP


    pop ProcessPaneMessage rbx
;==============================================================================
; UpdateAllPanes - Refresh all panes with current state
;==============================================================================
UpdateAllPanes PROC
    push rbx
    
    ; Update each pane type
    call UpdateEditorPanes
    call UpdateTerminalPanes  
    call UpdateChatPanes
    call UpdateDebugPanes
    
    pop ENDP


    pop UpdateAllPanes rbx
;==============================================================================
; Helper Functions (Minimal implementations)
;==============================================================================
EmbedAsmFeature PROC
    ; rcx = pane, rdx = handler
    ret
EmbedAsmFeature ENDP

UpdateEditorPanes PROC
    ret
UpdateEditorPanes ENDP

UpdateTerminalPanes PROC
    ret
UpdateTerminalPanes ENDP

UpdateChatPanes PROC
    ret
UpdateChatPanes ENDP

UpdateDebugPanes PROC
    ret
UpdateDebugPanes ENDP

; ASM feature handlers (referenced from pane_integration_system.asm)
EXTERN asm_syntax_handler:PROC
EXTERN asm_debug_handler:PROC

; Additional ASM chat handler
asm_chat_handler PROC
    ; rcx = pane, rdx = chat data
    ; Provide ASM-specific assistance in chat
    ret
asm_chat_handler ENDP

END




