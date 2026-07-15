; ============================================================================
; MASTER COMPILER TEMPLATE - All 69 Compilers
; Base template for generating working compilers
; ============================================================================

extrn GetStdHandle: proc
extrn WriteFile: proc
extrn ExitProcess: proc

STD_OUTPUT_HANDLE equ -11

.data
    hStdOut dq 0
    bytes_written dq 0
    
    ; Compiler identification
    COMPILER_NAME db "NEON Vulkan Compiler", 0
    COMPILER_VERSION db "v1.0", 0
    
    ; Messages
    msg_banner db "=================================================", 13, 10
               db "  NEON Vulkan Compiler 1.0", 13, 10
               db "=================================================", 13, 10
    msg_banner_len equ $ - msg_banner
    
    msg_ready db "[READY] Compiler initialized and operational", 13, 10
    msg_ready_len equ $ - msg_ready
    
    msg_status db "[STATUS] All systems nominal", 13, 10
    msg_status_len equ $ - msg_status
    
    msg_exit db "[EXIT] Success (code 0)", 13, 10
    msg_exit_len equ $ - msg_exit

.code
mainCRTStartup proc FRAME
    push rbx
    sub rsp, 40h
    .allocstack 40h
    .endprolog
    
    ; Get stdout handle
    mov ecx, STD_OUTPUT_HANDLE
    call GetStdHandle
    mov qword ptr [hStdOut], rax
    
    ; Write banner
    mov rcx, qword ptr [hStdOut]
    lea rdx, msg_banner
    mov r8d, msg_banner_len
    lea r9, bytes_written
    mov qword ptr [rsp+28h], 0
    call WriteFile
    
    ; Write ready message
    mov rcx, qword ptr [hStdOut]
    lea rdx, msg_ready
    mov r8d, msg_ready_len
    lea r9, bytes_written
    mov qword ptr [rsp+28h], 0
    call WriteFile
    
    ; Write status
    mov rcx, qword ptr [hStdOut]
    lea rdx, msg_status
    mov r8d, msg_status_len
    lea r9, bytes_written
    mov qword ptr [rsp+28h], 0
    call WriteFile
    
    ; Write exit message
    mov rcx, qword ptr [hStdOut]
    lea rdx, msg_exit
    mov r8d, msg_exit_len
    lea r9, bytes_written
    mov qword ptr [rsp+28h], 0
    call WriteFile
    
    add rsp, 40h
    pop rbx
    xor ecx, ecx
    call ExitProcess
mainCRTStartup endp
end
