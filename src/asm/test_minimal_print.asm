; =============================================================================
; test_minimal_print.asm
; Minimal test that just prints messages
; =============================================================================

include rawrxd_win64.inc

.DATA

; Output strings
msg_start db "Test starting...", 13, 10, 0
msg_middle db "Middle message...", 13, 10, 0
msg_exit db "Exiting...", 13, 10, 0

.CODE

; =============================================================================
; Main entry point
; =============================================================================
main PROC FRAME
    push rbx
    push rsi
    push rdi
    push r12
    .pushreg rbx
    .pushreg rsi
    .pushreg rdi
    .pushreg r12
    sub rsp, 28h
    .allocstack 28h
    .endprolog

    ; Print start message
    lea rcx, msg_start
    call print_cstring

    ; Print middle message
    lea rcx, msg_middle
    call print_cstring

    ; Print exit message
    lea rcx, msg_exit
    call print_cstring

    ; Exit
    xor ecx, ecx
    call ExitProcess

main ENDP

; =============================================================================
; print_cstring - Print null-terminated string
;   RCX = string pointer
; =============================================================================
print_cstring PROC FRAME
    push rbx
    push rsi
    push rdi
    push r12
    .pushreg rbx
    .pushreg rsi
    .pushreg rdi
    .pushreg r12
    sub rsp, 28h
    .allocstack 28h
    .endprolog

    mov rsi, rcx
    mov r12, rcx            ; Save original pointer
    
    ; Calculate length manually
    xor ebx, ebx            ; Length counter
    
@@count_loop:
    movzx eax, BYTE PTR [rsi + rbx]
    test al, al
    jz @@done_counting
    inc ebx
    cmp ebx, 1000
    jb @@count_loop
    
@@done_counting:
    test ebx, ebx
    jz @@exit               ; Empty string
    
    ; Write to stdout
    mov rcx, -11            ; STD_OUTPUT_HANDLE
    call GetStdHandle
    
    mov rcx, rax            ; hConsole
    mov rdx, r12            ; lpBuffer
    mov r8d, ebx            ; nNumberOfBytesToWrite
    xor r9, r9              ; lpNumberOfBytesWritten
    mov QWORD PTR [rsp+20h], 0  ; lpOverlapped
    call WriteFile

@@exit:
    add rsp, 28h
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
print_cstring ENDP

END
