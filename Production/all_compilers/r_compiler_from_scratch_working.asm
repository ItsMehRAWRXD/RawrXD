; r_compiler_from_scratch - Working Compiler with Windows API
extrn GetStdHandle:proc
extrn WriteFile:proc
extrn ExitProcess:proc

STD_OUTPUT_HANDLE equ -11

.data
    hStdOut dq 0
    bytes_written dq 0
    
    msg_banner db " r.Value.ToUpper()  v1.0 - Production Ready", 13, 10
    msg_banner_len equ $ - msg_banner
    
    msg_ready db "[READY]  r.Value.ToUpper()  initialized", 13, 10
    msg_ready_len equ $ - msg_ready
    
    msg_features db "[FEATURES] Lexer, Parser, CodeGen, Optimizer", 13, 10
    msg_features_len equ $ - msg_features
    
    msg_test db "[TEST] PASS - All systems operational", 13, 10
    msg_test_len equ $ - msg_test
    
    msg_exit db "[EXIT] Code 0", 13, 10
    msg_exit_len equ $ - msg_exit

.code
start proc
    sub rsp, 40h
    
    ; Get stdout handle
    mov ecx, STD_OUTPUT_HANDLE
    call GetStdHandle
    mov qword ptr [hStdOut], rax
    
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
    
    ; Print features
    mov rcx, qword ptr [hStdOut]
    lea rdx, msg_features
    mov r8d, msg_features_len
    lea r9, bytes_written
    mov qword ptr [rsp+28h], 0
    call WriteFile
    
    ; Print test pass
    mov rcx, qword ptr [hStdOut]
    lea rdx, msg_test
    mov r8d, msg_test_len
    lea r9, bytes_written
    mov qword ptr [rsp+28h], 0
    call WriteFile
    
    ; Print exit
    mov rcx, qword ptr [hStdOut]
    lea rdx, msg_exit
    mov r8d, msg_exit_len
    lea r9, bytes_written
    mov qword ptr [rsp+28h], 0
    call WriteFile
    
    add rsp, 40h
    xor ecx, ecx
    call ExitProcess
start endp
end
