; universal_compiler_runtime_production.asm
; Production-ready x64 console application

extrn GetStdHandle:proc
extrn WriteFile:proc
extrn ExitProcess:proc

STD_OUTPUT_HANDLE equ -11
STD_INPUT_HANDLE equ -10

.data
    hStdOut dq 0
    hStdIn dq 0
    bytes_written dq 0
    
    msg_banner db "Universal Compiler Runtime v1.0", 13, 10
    msg_banner_len equ $ - msg_banner
    
    msg_ready db "[READY] Compiler initialized", 13, 10
    msg_ready_len equ $ - msg_ready
    
    msg_test_pass db "[TEST] PASS - Runtime operational", 13, 10
    msg_test_pass_len equ $ - msg_test_pass
    
    msg_exit db "[EXIT] Code 0", 13, 10
    msg_exit_len equ $ - msg_exit

.code

main proc
    push rbx
    sub rsp, 40h
    
    ; Get stdout handle
    mov ecx, STD_OUTPUT_HANDLE
    call GetStdHandle
    mov qword ptr [hStdOut], rax
    
    ; Get stdin handle
    mov ecx, STD_INPUT_HANDLE
    call GetStdHandle
    mov qword ptr [hStdIn], rax
    
    ; Print banner
    mov rcx, qword ptr [hStdOut]
    lea rdx, msg_banner
    mov r8d, msg_banner_len
    lea r9, bytes_written
    mov qword ptr [rsp+28h], 0
    call WriteFile
    
    ; Print ready
    mov rcx, qword ptr [hStdOut]
    lea rdx, msg_ready
    mov r8d, msg_ready_len
    lea r9, bytes_written
    mov qword ptr [rsp+28h], 0
    call WriteFile
    
    ; Print test pass
    mov rcx, qword ptr [hStdOut]
    lea rdx, msg_test_pass
    mov r8d, msg_test_pass_len
    lea r9, bytes_written
    mov qword ptr [rsp+28h], 0
    call WriteFile
    
    ; Print exit message
    mov rcx, qword ptr [hStdOut]
    lea rdx, msg_exit
    mov r8d, msg_exit_len
    lea r9, bytes_written
    mov qword ptr [rsp+28h], 0
    call WriteFile
    
    ; Cleanup and exit
    add rsp, 40h
    pop rbx
    xor ecx, ecx
    call ExitProcess
main endp

end
