; ==================================================================================
; SOVEREIGN CONTEXT
; File: Sovereign_Context.asm
; Role: Execution State Snapshotting
; ==================================================================================

include Sovereign_Common.inc
include Sovereign_FrameABI.inc
include Sovereign_Telemetry.inc

.CODE

PUBLIC Sovereign_Context_Save
Sovereign_Context_Save PROC
    ; RCX = Ptr to SOVEREIGN_CONTEXT
    mov [rcx].SOVEREIGN_CONTEXT.Reg_RAX, rax
    mov [rcx].SOVEREIGN_CONTEXT.Reg_RBX, rbx
    
    ; FIX: Preserve original RCX pointer value
    mov rax, rcx 
    mov [rcx].SOVEREIGN_CONTEXT.Reg_RCX, rax
    
    mov [rcx].SOVEREIGN_CONTEXT.Reg_RDX, rdx
    mov [rcx].SOVEREIGN_CONTEXT.Reg_RSI, rsi
    mov [rcx].SOVEREIGN_CONTEXT.Reg_RDI, rdi
    mov [rcx].SOVEREIGN_CONTEXT.Reg_RBP, rbp
    mov [rcx].SOVEREIGN_CONTEXT.Reg_RSP, rsp
    mov [rcx].SOVEREIGN_CONTEXT.Reg_R8, r8
    mov [rcx].SOVEREIGN_CONTEXT.Reg_R9, r9
    mov [rcx].SOVEREIGN_CONTEXT.Reg_R10, r10
    mov [rcx].SOVEREIGN_CONTEXT.Reg_R11, r11
    mov [rcx].SOVEREIGN_CONTEXT.Reg_R12, r12
    mov [rcx].SOVEREIGN_CONTEXT.Reg_R13, r13
    mov [rcx].SOVEREIGN_CONTEXT.Reg_R14, r14
    mov [rcx].SOVEREIGN_CONTEXT.Reg_R15, r15
    ret
Sovereign_Context_Save ENDP

END
