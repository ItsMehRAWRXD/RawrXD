; =============================================================================
; test_decoder_minimal.asm
; Minimal test of multi-architecture decoder
; =============================================================================

include rawrxd_win64.inc

; External functions from RawrCodex.asm
EXTERN RawrDisasm_ARM_Decode:PROC

; Architecture constants
ARCH_ARM_64   EQU 3

.DATA

; ARM64: mov x0, #0x1234; ret  
test_arm64 db 000h, 002h, 082h, 0D2h, 0C0h, 003h, 05Fh, 0D6h

; Output strings
msg_start db "Test starting...", 13, 10, 0
msg_before db "Before decode call", 13, 10, 0
msg_after db "After decode call", 13, 10, 0
msg_result db "Result: ", 0
msg_ok db "OK", 13, 10, 0
msg_fail db "FAIL", 13, 10, 0
msg_exit db "Exiting...", 13, 10, 0

; Instruction structure
ALIGN 8
instr_result db 128 dup(0)

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
    sub rsp, 30h
    .allocstack 30h
    .endprolog

    ; Print start message
    lea rcx, msg_start
    call print_cstring

    ; Print before message
    lea rcx, msg_before
    call print_cstring

    ; Set up parameters for RawrDisasm_ARM_Decode
    ; RCX = context (NULL)
    ; EDX = arch type (ARCH_ARM_64 = 3)
    ; R8  = VA (0)
    ; R9  = instruction bytes
    ; [RSP+28h] = output struct
    
    xor ecx, ecx                    ; context = NULL
    mov edx, ARCH_ARM_64            ; arch type
    xor r8, r8                      ; VA = 0
    lea r9, test_arm64              ; instruction bytes
    
    lea rax, instr_result
    mov QWORD PTR [rsp+28h], rax    ; output struct
    
    ; Print result prefix
    lea rcx, msg_result
    call print_cstring
    
    ; Call the decoder
    call RawrDisasm_ARM_Decode
    
    ; Check result
    test eax, eax
    jz @@fail
    
    lea rcx, msg_ok
    call print_cstring
    jmp @@exit
    
@@fail:
    lea rcx, msg_fail
    call print_cstring

@@exit:
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
