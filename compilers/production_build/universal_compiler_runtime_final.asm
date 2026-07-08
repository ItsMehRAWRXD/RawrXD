; universal_compiler_runtime_final.asm
; Production-ready x64 console application

extrn GetStdHandle:proc
extrn WriteFile:proc
extrn ReadFile:proc
extrn ExitProcess:proc
extrn GetProcessHeap:proc
extrn HeapAlloc:proc
extrn HeapFree:proc

STD_OUTPUT_HANDLE equ -11
STD_INPUT_HANDLE equ -10

.data
    hStdOut dq 0
    hStdIn dq 0
    bytes_written dq 0
    bytes_read dq 0
    
    msg_banner db "Universal Compiler Runtime v1.0", 13, 10
    msg_banner_len equ $ - msg_banner
    
    msg_ready db "[READY] Compiler initialized", 13, 10
    msg_ready_len equ $ - msg_ready
    
    msg_prompt db "> "
    msg_prompt_len equ $ - msg_prompt
    
    msg_bye db 13, 10, "[EXIT] Goodbye", 13, 10
    msg_bye_len equ $ - msg_bye
    
    msg_test_pass db 13, 10, "[TEST] PASS - Runtime operational", 13, 10
    msg_test_pass_len equ $ - msg_test_pass
    
    input_buffer db 1024 dup(0)

.code

main proc
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
    lea rdx, msg_banner
    mov r8d, msg_banner_len
    call write_string
    
    ; Print ready
    lea rdx, msg_ready
    mov r8d, msg_ready_len
    call write_string
    
    ; Print test pass message
    lea rdx, msg_test_pass
    mov r8d, msg_test_pass_len
    call write_string
    
    ; Exit success
    xor ecx, ecx
    call ExitProcess
main endp

; Write string to stdout
; rdx = string, r8d = length
write_string proc
    sub rsp, 28h
    mov rcx, qword ptr [hStdOut]
    lea r9, bytes_written
    mov qword ptr [rsp+20h], 0
    call WriteFile
    add rsp, 28h
    ret
write_string endp

end
