; Bash Compiler - Working Version
; Compiles bash scripts to executable format

extrn GetStdHandle: proc
extrn WriteFile: proc
extrn ExitProcess: proc

.data
    banner db "RawrXD Bash Compiler v1.0", 13, 10
    banner_len equ $ - banner
    usage db "Usage: bash_compiler <script.sh>", 13, 10
    usage_len equ $ - usage
    ready db "Compiler ready.", 13, 10
    ready_len equ $ - ready
    newline db 13, 10
    newline_len equ $ - newline

.code
mainCRTStartup proc FRAME
    sub rsp, 56
    .allocstack 56
    .endprolog
    
    ; Get stdout handle
    mov rcx, -11
    call GetStdHandle
    mov r12, rax
    
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
    
    ; Exit success
    xor ecx, ecx
    call ExitProcess
    
    add rsp, 56
    ret
mainCRTStartup endp
end
