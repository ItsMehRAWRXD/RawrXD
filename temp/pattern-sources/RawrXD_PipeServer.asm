; ============================================================================
; RawrXD Pipe Server - MASM Stub
; Generated: 2026-01-26 06:43:06
; Toolchain: PowerShell masm64.ps1/link64.ps1 compatible
; Exports (via DEF): StartPipeServer, StopPipeServer
; ============================================================================

option casemap:none
<<<<<<< HEAD

; ─── Cross-module symbol resolution ───
INCLUDE rawrxd_master.inc

=======
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
option win64:3

.code

StartPipeServer PROC
    xor eax, eax
    ret
StartPipeServer ENDP

StopPipeServer PROC
    xor eax, eax
    ret
StopPipeServer ENDP

END
