; Universal Compiler Runtime - Working Version
; RawrXD Compiler Infrastructure

extrn GetStdHandle: proc
extrn WriteFile: proc
extrn ExitProcess: proc

.data
    banner db "RawrXD Universal Compiler Runtime v1.0", 13, 10
    banner_len equ $ - banner
    ready db "Ready for input...", 13, 10
    ready_len equ $ - ready
    prompt db "> "
    prompt_len equ $ - prompt
    
.code

mainCRTStartup proc FRAME
    ; Allocate shadow space + align to 16 bytes
    sub rsp, 56
    .allocstack 56
    .endprolog
    
    ; Get stdout handle
    mov rcx, -11              ; STD_OUTPUT_HANDLE
    call GetStdHandle
    mov r12, rax              ; Save handle
    
    ; Write banner
    mov rcx, r12
    lea rdx, banner
    mov r8d, banner_len
    xor r9d, r9d
    lea rax, [rsp+32]
    mov qword ptr [rax], r9
    call WriteFile
    
    ; Write ready message
    mov rcx, r12
    lea rdx, ready
    mov r8d, ready_len
    xor r9d, r9d
    lea rax, [rsp+32]
    mov qword ptr [rax], r9
    call WriteFile
    
    ; Exit with code 0
    xor ecx, ecx
    call ExitProcess
    
    add rsp, 56
    ret
mainCRTStartup endp

end
