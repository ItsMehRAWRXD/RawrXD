; Minimal working x64 assembly program
; Uses proper stack alignment and calling convention

extrn ExitProcess: proc

.code

mainCRTStartup proc FRAME
    ; Allocate shadow space + align to 16 bytes
    sub rsp, 40
    .allocstack 40
    .endprolog
    
    ; Exit with code 0
    xor ecx, ecx
    call ExitProcess
    
    ; Should never reach here
    add rsp, 40
    ret
mainCRTStartup endp

end
