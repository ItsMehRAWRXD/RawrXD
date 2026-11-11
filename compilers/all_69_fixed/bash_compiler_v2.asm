; Bash Compiler v2 v2.0 - Shell 
extrn GetStdHandle: proc 
extrn WriteFile: proc 
extrn ExitProcess: proc 
 
STD_OUTPUT_HANDLE equ -11 
 
.data 
    hStdOut dq 0 
    bytes_written dq 0 
    msg_banner db "Bash Compiler v2 v2.0", 13, 10 
    msg_banner_len equ $ - msg_banner 
    msg_ready db "[READY] Shell compiler operational", 13, 10 
    msg_ready_len equ $ - msg_ready 
    msg_exit db "[EXIT] Code 0", 13, 10 
    msg_exit_len equ $ - msg_exit 
 
.code 
mainCRTStartup proc FRAME 
    sub rsp, 58h 
    .allocstack 58h 
    .endprolog 
 
    mov ecx, -11 
    call GetStdHandle 
    mov qword ptr [hStdOut], rax 
 
    mov rcx, qword ptr [hStdOut] 
    lea rdx, msg_banner 
    mov r8d, msg_banner_len 
    xor r9d, r9d 
    lea rax, [rsp+20h] 
    mov qword ptr [rax], r9 
    call WriteFile 
 
    mov rcx, qword ptr [hStdOut] 
    lea rdx, msg_ready 
    mov r8d, msg_ready_len 
    xor r9d, r9d 
    lea rax, [rsp+20h] 
    mov qword ptr [rax], r9 
    call WriteFile 
 
    mov rcx, qword ptr [hStdOut] 
    lea rdx, msg_exit 
    mov r8d, msg_exit_len 
    xor r9d, r9d 
    lea rax, [rsp+20h] 
    mov qword ptr [rax], r9 
    call WriteFile 
 
    add rsp, 58h 
    xor ecx, ecx 
    call ExitProcess 
mainCRTStartup endp 
end 
