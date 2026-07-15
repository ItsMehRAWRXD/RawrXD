; Test
extrn GetStdHandle: proc
extrn WriteFile: proc
extrn ExitProcess: proc

.data
    banner db "Test", 13, 10
    banner_len equ $ - banner
.code
mainCRTStartup proc FRAME
    sub rsp, 56
    .allocstack 56
    .endprolog
    mov rcx, -11
    call GetStdHandle
    xor ecx, ecx
    call ExitProcess
    add rsp, 56
    ret
mainCRTStartup endp
end
