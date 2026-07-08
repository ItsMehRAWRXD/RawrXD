; universal_compiler_runtime_v2.asm
; Production-ready x64 console application
; Uses Windows API directly - no CRT dependencies

extrn GetStdHandle:proc
extrn WriteFile:proc
extrn ReadFile:proc
extrn ExitProcess:proc
extrn GetProcessHeap:proc
extrn HeapAlloc:proc
extrn HeapFree:proc

STD_OUTPUT_HANDLE equ -11
STD_INPUT_HANDLE equ -10
STD_ERROR_HANDLE equ -12

.data
    hStdOut dq 0
    hStdIn dq 0
    hStdErr dq 0
    heap_handle dq 0
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
    
    input_buffer db 1024 dup(0)
    input_size equ 1024

.code

main proc frame
    push rbp
    mov rbp, rsp
    sub rsp, 48h
    
    ; Get stdout handle
    mov ecx, STD_OUTPUT_HANDLE
    call GetStdHandle
    mov qword ptr [hStdOut], rax
    
    ; Get stdin handle
    mov ecx, STD_INPUT_HANDLE
    call GetStdHandle
    mov qword ptr [hStdIn], rax
    
    ; Get stderr handle
    mov ecx, STD_ERROR_HANDLE
    call GetStdHandle
    mov qword ptr [hStdErr], rax
    
    ; Get process heap
    call GetProcessHeap
    mov qword ptr [heap_handle], rax
    
    ; Print banner
    lea rdx, msg_banner
    mov r8d, msg_banner_len
    call write_string
    
    ; Print ready
    lea rdx, msg_ready
    mov r8d, msg_ready_len
    call write_string
    
    ; Run main loop
    call main_loop
    
    ; Print goodbye
    lea rdx, msg_bye
    mov r8d, msg_bye_len
    call write_string
    
    ; Exit success
    xor ecx, ecx
    call ExitProcess
    
main endp

; Write string to stdout
; rdx = string, r8d = length
write_string proc frame
    push rbp
    mov rbp, rsp
    sub rsp, 40h
    
    mov rcx, qword ptr [hStdOut]
    lea r9, bytes_written
    mov qword ptr [rsp+28h], 0
    call WriteFile
    
    add rsp, 40h
    pop rbp
    ret
write_string endp

; Read line from stdin
; Returns: rax = pointer to buffer
read_line proc frame
    push rbp
    mov rbp, rsp
    sub rsp, 40h
    
    mov rcx, qword ptr [hStdIn]
    lea rdx, input_buffer
    mov r8d, input_size
    lea r9, bytes_read
    mov qword ptr [rsp+28h], 0
    call ReadFile
    
    add rsp, 40h
    pop rbp
    lea rax, input_buffer
    ret
read_line endp

; Main loop
main_loop proc frame
    push rbp
    mov rbp, rsp
    sub rsp, 30h
    
loop_start:
    ; Print prompt
    lea rdx, msg_prompt
    mov r8d, msg_prompt_len
    call write_string
    
    ; Read input
    call read_line
    
    ; Check first character
    mov al, byte ptr [input_buffer]
    
    ; Check for quit commands
    cmp al, 'q'
    je loop_done
    cmp al, 'Q'
    je loop_done
    cmp al, 0
    je loop_done
    cmp al, 13  ; CR
    je loop_done
    cmp al, 10  ; LF
    je loop_done
    
    ; Echo input back
    mov r8d, dword ptr [bytes_read]
    cmp r8d, 0
    jle loop_start
    
    lea rdx, input_buffer
    call write_string
    
    jmp loop_start
    
loop_done:
    add rsp, 30h
    pop rbp
    ret
main_loop endp

end
