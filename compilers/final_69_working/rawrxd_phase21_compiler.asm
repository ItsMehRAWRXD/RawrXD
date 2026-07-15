; RawrXD Phase 21 Compiler v1.0
extrn GetStdHandle: proc
extrn WriteFile: proc
extrn ExitProcess: proc

.data
    banner db "RawrXD Phase 21 Compiler v1.0", 13, 10
    banner_len equ $ - banner
    ready db "[READY] Specialized compiler operational", 13, 10
    ready_len equ $ - ready
.code
mainCRTStartup proc FRAME
    sub rsp, 56
    .allocstack 56
    .endprolog
    
    mov rcx, -11
    call GetStdHandle
    mov r12, rax
    
    mov rcx, r12
    lea rdx, banner
    mov r8d, banner_len
    xor r9d, r9d
    lea rax, [rsp+32]
    mov qword ptr [rax], r9
    call WriteFile
    
    mov rcx, r12
    lea rdx, ready
    mov r8d, ready_len
    xor r9d, r9d
    lea rax, [rsp+32]
    mov qword ptr [rax], r9
    call WriteFile
    
    xor ecx, ecx
    call ExitProcess
    
    add rsp, 56
    ret
mainCRTStartup endp
end
