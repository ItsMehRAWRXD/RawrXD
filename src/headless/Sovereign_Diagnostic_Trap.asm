; =========================================================================================
; SOVEREIGN DIAGNOSTIC TRAP
; Structural failure intercept engine and panic state handler.
; Captures execution failures and isolates hardware register state for telemetry logs.
; =========================================================================================

OPTION CASEMAP:NONE

PUBLIC XR_Diagnostic_Raise_Assert
PUBLIC XR_Diagnostic_Capture_Register_Dump
PUBLIC g_Crash_Dump_Address
PUBLIC g_Assert_Failed_Flag

.DATA
    ALIGN 8
    g_Crash_Dump_Address dq 0
    g_Assert_Failed_Flag dd 0

.CODE

; -----------------------------------------------------------------------------------------
; XR_Diagnostic_Raise_Assert
; RCX = evaluated boolean state result (non-zero passes)
; RDX = unique 32-bit location identification trap tag
; -----------------------------------------------------------------------------------------
ALIGN 16
XR_Diagnostic_Raise_Assert PROC
    test rcx, rcx
    jz @@assert_violation_trap
    ret

@@assert_violation_trap:
    mov dword ptr [g_Assert_Failed_Flag], edx
    mov rax, [rsp]
    mov [g_Crash_Dump_Address], rax
    int 3
    ret
XR_Diagnostic_Raise_Assert ENDP

; -----------------------------------------------------------------------------------------
; XR_Diagnostic_Capture_Register_Dump
; RCX = destination base address for a 512-byte telemetry block
; Layout: 16 GPR qwords at +0, YMM0-YMM3 at +128.
; -----------------------------------------------------------------------------------------
ALIGN 16
XR_Diagnostic_Capture_Register_Dump PROC
    mov [rcx], rax
    mov [rcx + 8], rbx
    mov [rcx + 16], rcx
    mov [rcx + 24], rdx
    mov [rcx + 32], rbp
    mov [rcx + 40], rsi
    mov [rcx + 48], rdi
    mov [rcx + 56], rsp
    mov [rcx + 64], r8
    mov [rcx + 72], r9
    mov [rcx + 80], r10
    mov [rcx + 88], r11
    mov [rcx + 96], r12
    mov [rcx + 104], r13
    mov [rcx + 112], r14
    mov [rcx + 120], r15

    vmovdqu ymmword ptr [rcx + 128], ymm0
    vmovdqu ymmword ptr [rcx + 160], ymm1
    vmovdqu ymmword ptr [rcx + 192], ymm2
    vmovdqu ymmword ptr [rcx + 224], ymm3

    ret
XR_Diagnostic_Capture_Register_Dump ENDP

END