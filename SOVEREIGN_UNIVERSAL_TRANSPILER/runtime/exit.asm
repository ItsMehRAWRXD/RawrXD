; exit.asm - Runtime exit helper
; Provides native program termination without CRT

extrn ExitProcess:proc

.code

; RuntimeExit - Exit program with code
; RCX = exit code
RuntimeExit PROC
    ; Just pass through to ExitProcess
    call ExitProcess
    ; Never returns
RuntimeExit ENDP

; RuntimeAbort - Abnormal termination
RuntimeAbort PROC
    mov ecx, 1          ; Exit code 1
    call ExitProcess
RuntimeAbort ENDP

END
