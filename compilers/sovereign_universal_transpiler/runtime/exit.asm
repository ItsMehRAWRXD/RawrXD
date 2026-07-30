; exit.asm - Native process termination for Sovereign Universal Transpiler

extrn ExitProcess:proc

.code

; RuntimeExit - Terminate the process
; RCX = exit code
RuntimeExit PROC
    call ExitProcess
    ret
RuntimeExit ENDP

end