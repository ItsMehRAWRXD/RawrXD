;===============================================================================
; RawrXD_Common.inc — Shared MASM x64 foundation for RawrXD hand-written asm.
;===============================================================================
; Common Win64/x64 ABI constants and reusable frame macros shared across the
; RawrXD native-assembly modules. Pure assembly modules include this so they
; share one authoritative definition of the ABI constants. Modules that only
; perform core math (e.g. the HexMag polymorphic repeat tuner) need no kernel32
; imports; the import declarations below are optional and left commented out by
; design so a math-only translation unit never pulls a runtime dependency.
;===============================================================================

IFNDEF RAWRXD_COMMON_INC
RAWRXD_COMMON_INC EQU 1

;-------------------------------------------------------------------------------
; Win64 x64 ABI constants (Microsoft x64 calling convention)
;-------------------------------------------------------------------------------
SHADOW_SPACE_SIZE EQU 20h        ; 32-byte home ("shadow") space per call
STACK_ALIGNMENT   EQU 10h        ; rsp must be 16-byte aligned at a call boundary

;-------------------------------------------------------------------------------
; Reusable frame macros
;-------------------------------------------------------------------------------
; PUSH_CALLEE_SAVED / POP_CALLEE_SAVED preserve the Win64 callee-saved GPRs.
; They must be issued in strict LIFO order (push on entry, pop before ret) and
; the surrounding procedure is responsible for keeping rsp 16-byte aligned.
PUSH_CALLEE_SAVED macro
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
endm

POP_CALLEE_SAVED macro
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
endm

; ALIGN_STACK bytes  — reserve `bytes` of locals and re-align rsp to 16 bytes.
; After the CALL pushed the return address (8) and this macro pushes rbp (8),
; rsp is 16-aligned on entry; subtracting a 16-multiple of locals preserves it.
; `bytes` MUST be a multiple of 16.  Usage mirrors:
;     push rbp
;     mov  rbp, rsp
;     ALIGN_STACK 20h
ALIGN_STACK macro bytes:req
    sub rsp, bytes
endm

ENDIF ; RAWRXD_COMMON_INC
