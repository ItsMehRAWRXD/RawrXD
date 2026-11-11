; LinkageFixes.inc — MASM x64 linkage directives for C++ interop
; Include this at the top of any .asm file that exports symbols to C++.
;
; Usage:
;   INCLUDE LinkageFixes.inc
;
; This ensures:
;   1. Case preservation (OPTION CASEMAP:NONE)
;   2. Explicit PUBLIC declarations for all exported symbols
;   3. Proper x64 calling convention (Microsoft x64 fastcall)
;   4. FRAME prolog for stack unwinding

OPTION CASEMAP:NONE
OPTION PROLOGUE:NONE
OPTION EPILOGUE:NONE

; ---------------------------------------------------------------------------
; Export macros — use these instead of raw PUBLIC directives
; ---------------------------------------------------------------------------

; Export a PROC with proper PUBLIC declaration
EXPORT_FUNC MACRO funcName:REQ
    PUBLIC funcName
    funcName PROC FRAME
ENDM

; End an exported PROC
ENDFUNC MACRO funcName:REQ
    funcName ENDP
ENDM

; Export a DATA symbol
EXPORT_DATA MACRO dataName:REQ
    PUBLIC dataName
ENDM

; ---------------------------------------------------------------------------
; Standard prolog/epilog for x64 functions
; ---------------------------------------------------------------------------

; Standard prolog: save non-volatile registers, allocate stack frame
STD_PROLOG MACRO frameSize:REQ
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    sub rsp, frameSize
    .allocstack frameSize
ENDM

; Standard epilog: restore registers, return
STD_EPILOG MACRO
    add rsp, (frameSize)
    pop rbp
    ret
ENDM

; ---------------------------------------------------------------------------
; Calling convention helpers
; ---------------------------------------------------------------------------

; Microsoft x64 calling convention:
;   RCX = first parameter
;   RDX = second parameter
;   R8  = third parameter
;   R9  = fourth parameter
;   Stack = fifth+ parameters
;   Return value in RAX
;   Caller cleans stack (no __stdcall difference on x64)

; ---------------------------------------------------------------------------
; Common kernel export declarations
; ---------------------------------------------------------------------------

; Inference kernel exports (used by Deep2Bridge)
EXPORT_DATA sovereign_q4k_gemv
EXPORT_DATA sovereign_deep2_kernels

; Runtime bridge exports (used by RawrXDMain.asm)
EXPORT_DATA RawrXD_InitializePlatform
EXPORT_DATA RawrXD_ShutdownPlatform
EXPORT_DATA RawrXD_PumpMessageQueue
EXPORT_DATA RawrXD_IsPlatformRunning
EXPORT_DATA RawrXD_SignalPlatformPanic

END
