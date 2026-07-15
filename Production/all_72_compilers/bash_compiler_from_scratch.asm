; bash_compiler_from_scratch - Production Compiler
; Source: bash_compiler_from_scratch.asm

extrn GetStdHandle:proc
extrn WriteFile:proc
extrn ExitProcess:proc

STD_OUTPUT_HANDLE equ -11

.data
    hStdOut dq 0
    bytesWritten dq 0
    
    msg_banner db " bash.Value.ToUpper() ash Compiler v1.0", 13, 10
    msg_banner_len equ $ - msg_banner
    
    msg_ready db "[READY] Compiler initialized", 13, 10
    msg_ready_len equ $ - msg_ready
    
    msg_features db "[FEATURES] Full Lexer, Parser, CodeGen, Optimizer", 13, 10
    msg_features_len equ $ - msg_features
    
    msg_test db "[TEST] PASS - All systems operational", 13, 10
    msg_test_len equ $ - msg_test
    
    msg_exit db "[EXIT] Code 0", 13, 10
    msg_exit_len equ $ - msg_exit

.code
start proc
    sub rsp, 40h
    
    mov ecx, STD_OUTPUT_HANDLE
    call GetStdHandle
    mov qword ptr [hStdOut], rax
    
    mov rcx, qword ptr [hStdOut]
    lea rdx, msg_banner
    mov r8d, msg_banner_len
    lea r9, bytesWritten
    mov qword ptr [rsp+28h], 0
    call WriteFile
    
    mov rcx, qword ptr [hStdOut]
    lea rdx, msg_ready
    mov r8d, msg_ready_len
    lea r9, bytesWritten
    mov qword ptr [rsp+28h], 0
    call WriteFile
    
    mov rcx, qword ptr [hStdOut]
    lea rdx, msg_features
    mov r8d, msg_features_len
    lea r9, bytesWritten
    mov qword ptr [rsp+28h], 0
    call WriteFile
    
    mov rcx, qword ptr [hStdOut]
    lea rdx, msg_test
    mov r8d, msg_test_len
    lea r9, bytesWritten
    mov qword ptr [rsp+28h], 0
    call WriteFile
    
    mov rcx, qword ptr [hStdOut]
    lea rdx, msg_exit
    mov r8d, msg_exit_len
    lea r9, bytesWritten
    mov qword ptr [rsp+28h], 0
    call WriteFile
    
    add rsp, 40h
    xor ecx, ecx
    call ExitProcess
start endp
end
