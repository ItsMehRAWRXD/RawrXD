; ============================================================================
; RawrXD_SovereignEntry.asm — Sovereign Binary Entry Point
; ============================================================================
; Target: x64 MASM (Microsoft Macro Assembler)
; Purpose: CRT-free entry point for RawrXD Sovereign Hot Lap.
;
; The OS loader jumps directly here. No CRT init, no global constructors,
; no locale setup, no buffer security checks. Just stack alignment and
; straight to the ECU governor.
;
; Build: ml64 /c /nologo RawrXD_SovereignEntry.asm
; Link:  link /NODEFAULTLIB /ENTRY:RawrXD_Entry /SUBSYSTEM:CONSOLE
;        RawrXD_SovereignMain.obj RawrXD_SovereignEntry.obj
;        kernel32.lib vulkan-1.lib
; ============================================================================

OPTION CASEMAP:NONE

; ============================================================================
; External linkage — C bridge functions and kernel32
; ============================================================================

EXTERN Engine_Init : PROC
EXTERN ECU_Loop    : PROC
EXTERN ExitProcess : PROC

; ============================================================================
; .CODE segment — the only segment we need
; ============================================================================

.CODE

; ----------------------------------------------------------------------------
; RawrXD_Entry — Sovereign entry point
; ----------------------------------------------------------------------------
; OS loader jumps here directly. Stack is unaligned on entry; we fix it
; before any calls. No argc/argv — the C bridge handles that if needed.
; ----------------------------------------------------------------------------

RawrXD_Entry PROC PUBLIC
    ; Win64 ABI: 16-byte stack alignment before CALL
    ; On entry RSP is 8-byte aligned (return address pushed by OS).
    ; We need 16-byte alignment for the first CALL.
    ; Shadow space (32 bytes) + 8 bytes alignment = 40 bytes.
    sub rsp, 40

    ; 1. Initialize the engine (Vulkan, arena, proc table)
    call Engine_Init

    ; Check return code — if non-zero, bail out immediately
    test eax, eax
    jnz Bail

    ; 2. Enter the sovereign governor loop
    ; This runs until inference completes or a fatal error occurs.
    call ECU_Loop

    ; 3. Clean shutdown — exit code in EAX from ECU_Loop
Bail:
    ; Move return code to RCX (first arg for Win64)
    mov ecx, eax
    ; Sign-extend to 64-bit if negative
    movsxd rcx, ecx

    ; Call kernel32!ExitProcess — never returns
    call ExitProcess

    ; NORETURN — ExitProcess does not return, but we keep a trap
    ; in case something goes catastrophically wrong.
    int 3
RawrXD_Entry ENDP

END
