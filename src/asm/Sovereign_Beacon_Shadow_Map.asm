; ==================================================================================
; SOVEREIGN BEACON SHADOW MAP
; File: Sovereign_Beacon_Shadow_Map.asm
; Role: Asynchronous DAG State Tracking and Dependency Governance
; ==================================================================================

include Sovereign_Common.inc
include Sovereign_FrameABI.inc

SHADOW_STATE_PENDING EQU 0
SHADOW_STATE_READY   EQU 1
SHADOW_STATE_BUSY    EQU 2
SHADOW_STATE_DONE    EQU 3

.DATA
    ALIGN 64
    g_ShadowMap QWORD 4096 DUP(0)
    g_ShadowHead QWORD 0

.CODE

PUBLIC Sovereign_Shadow_Init
Sovereign_Shadow_Init PROC
    push rdi
    xor rax, rax
    mov rcx, 4096
    lea rdi, [g_ShadowMap]
    rep stosq
    pop rdi
    ret
Sovereign_Shadow_Init ENDP

PUBLIC Sovereign_Shadow_Update
Sovereign_Shadow_Update PROC
    ; RCX = Index, RDX = State
    lea r8, [g_ShadowMap + rcx*8]
    xchg [r8], rdx
    ret
Sovereign_Shadow_Update ENDP

PUBLIC Sovereign_Shadow_Acquire
Sovereign_Shadow_Acquire PROC
    ; RCX = Index
    lea r8, [g_ShadowMap + rcx*8]
    mov rax, SHADOW_STATE_BUSY
    lock xchg [r8], rax
    ret
Sovereign_Shadow_Acquire ENDP

PUBLIC Sovereign_Shadow_Wait
Sovereign_Shadow_Wait PROC
    ; RCX = Index
    lea r8, [g_ShadowMap + rcx*8]
@@Spin:
    mov rax, [r8]
    cmp rax, SHADOW_STATE_DONE
    je @@Done
    pause
    jmp @@Spin
@@Done:
    ret
Sovereign_Shadow_Wait ENDP

END