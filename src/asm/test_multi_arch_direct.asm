; =============================================================================
; test_multi_arch_direct.asm
; Direct test of multi-architecture decoder functions
; =============================================================================

include rawrxd_win64.inc

; External functions from RawrCodex.asm
EXTERN RawrDisasm_ARM_Decode:PROC
EXTERN RawrDisasm_MIPS_Decode:PROC
EXTERN RawrDisasm_RISCV_Decode:PROC

; Architecture constants
ARCH_X86_32   EQU 0
ARCH_X86_64   EQU 1
ARCH_ARM_32   EQU 2
ARCH_ARM_64   EQU 3
ARCH_THUMB    EQU 4
ARCH_THUMB2   EQU 5
ARCH_MIPS_32  EQU 6
ARCH_MIPS_64  EQU 7
ARCH_RISCV_32 EQU 8
ARCH_RISCV_64 EQU 9

; Test data section
.data

; x86-64: mov rax, 0x1234; ret
test_x86_64 db 048h, 0C7h, 0C0h, 034h, 012h, 000h, 000h, 0C3h
test_x86_64_len equ $ - test_x86_64

; ARM64: mov x0, #0x1234; ret  
test_arm64 db 000h, 002h, 082h, 0D2h, 0C0h, 003h, 05Fh, 0D6h
test_arm64_len equ $ - test_arm64

; ARM32: mov r0, #0x1234; bx lr
test_arm32 db 034h, 012h, 000h, 0E3h, 01Eh, 0FFh, 02Fh, 0E1h
test_arm32_len equ $ - test_arm32

; Thumb: movs r0, #0x34; bx lr
test_thumb db 034h, 020h, 070h, 047h
test_thumb_len equ $ - test_thumb

; MIPS: li $v0, 0x1234; jr $ra
test_mips db 034h, 012h, 002h, 024h, 008h, 000h, 0E0h, 003h
test_mips_len equ $ - test_mips

; RISC-V: li a0, 0x1234; ret
test_riscv db 013h, 015h, 082h, 001h, 067h, 080h, 000h, 000h
test_riscv_len equ $ - test_riscv

; Output strings
msg_header db "RawrCodex Multi-Architecture Decoder Test", 13, 10
msg_header_len equ $ - msg_header

msg_arm64 db "ARM64:  ", 0
msg_arm32 db "ARM32:  ", 0
msg_thumb db "Thumb:  ", 0
msg_mips db "MIPS:   ", 0
msg_riscv db "RISC-V: ", 0

msg_ok db " OK", 13, 10, 0
msg_fail db " FAIL", 13, 10, 0

; Instruction structure (simplified)
ALIGN 8
instr_result db 128 dup(0)

; Code section
.code

; =============================================================================
; Main entry point
; =============================================================================
main PROC FRAME
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    .pushreg rbx
    .pushreg rsi
    .pushreg rdi
    .pushreg r12
    .pushreg r13
    .pushreg r14
    .pushreg r15
    sub rsp, 40h
    .allocstack 40h
    .endprolog

    ; Print header
    lea rcx, msg_header
    mov edx, msg_header_len
    call print_string

    ; Test ARM64
    lea rcx, msg_arm64
    call print_cstring
    lea rcx, test_arm64
    mov edx, test_arm64_len
    mov r8d, ARCH_ARM_64
    call test_arm_decode
    
    ; Test ARM32
    lea rcx, msg_arm32
    call print_cstring
    lea rcx, test_arm32
    mov edx, test_arm32_len
    mov r8d, ARCH_ARM_32
    call test_arm_decode
    
    ; Test Thumb
    lea rcx, msg_thumb
    call print_cstring
    lea rcx, test_thumb
    mov edx, test_thumb_len
    mov r8d, ARCH_THUMB
    call test_arm_decode
    
    ; Test MIPS
    lea rcx, msg_mips
    call print_cstring
    lea rcx, test_mips
    mov edx, test_mips_len
    mov r8d, ARCH_MIPS_32
    call test_mips_decode
    
    ; Test RISC-V
    lea rcx, msg_riscv
    call print_cstring
    lea rcx, test_riscv
    mov edx, test_riscv_len
    mov r8d, ARCH_RISCV_32
    call test_riscv_decode

    ; Exit
    xor ecx, ecx
    call ExitProcess

main ENDP

; =============================================================================
; test_arm_decode - Test ARM decoder
;   RCX = code pointer
;   EDX = code length
;   R8D = arch type
; =============================================================================
test_arm_decode PROC FRAME
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

    mov rsi, rcx            ; RSI = code pointer
    mov ebx, edx            ; EBX = code length
    mov r12d, r8d           ; R12D = arch type
    
    ; Call RawrDisasm_ARM_Decode
    ; RCX = context (NULL)
    ; EDX = arch type
    ; R8  = VA (0)
    ; R9  = instruction bytes
    ; [RSP+28h] = output struct
    
    xor ecx, ecx            ; context = NULL
    mov edx, r12d           ; arch type
    xor r8, r8              ; VA = 0
    mov r9, rsi             ; instruction bytes
    
    lea rax, instr_result
    mov QWORD PTR [rsp+28h], rax
    
    call RawrDisasm_ARM_Decode
    
    ; Check result (EAX = bytes consumed)
    test eax, eax
    jz @@fail
    
    ; Print OK
    lea rcx, msg_ok
    call print_cstring
    jmp @@done
    
@@fail:
    lea rcx, msg_fail
    call print_cstring
    
@@done:
    add rsp, 28h
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
test_arm_decode ENDP

; =============================================================================
; test_mips_decode - Test MIPS decoder
;   RCX = code pointer
;   EDX = code length
;   R8D = arch type
; =============================================================================
test_mips_decode PROC FRAME
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

    mov rsi, rcx            ; RSI = code pointer
    mov ebx, edx            ; EBX = code length
    mov r12d, r8d           ; R12D = arch type
    
    ; Call RawrDisasm_MIPS_Decode
    xor ecx, ecx            ; context = NULL
    mov edx, r12d           ; arch type
    xor r8, r8              ; VA = 0
    mov r9, rsi             ; instruction bytes
    
    lea rax, instr_result
    mov QWORD PTR [rsp+28h], rax
    
    call RawrDisasm_MIPS_Decode
    
    ; Check result (EAX = bytes consumed)
    test eax, eax
    jz @@fail
    
    ; Print OK
    lea rcx, msg_ok
    call print_cstring
    jmp @@done
    
@@fail:
    lea rcx, msg_fail
    call print_cstring
    
@@done:
    add rsp, 28h
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
test_mips_decode ENDP

; =============================================================================
; test_riscv_decode - Test RISC-V decoder
;   RCX = code pointer
;   EDX = code length
;   R8D = arch type
; =============================================================================
test_riscv_decode PROC FRAME
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

    mov rsi, rcx            ; RSI = code pointer
    mov ebx, edx            ; EBX = code length
    mov r12d, r8d           ; R12D = arch type
    
    ; Call RawrDisasm_RISCV_Decode
    xor ecx, ecx            ; context = NULL
    mov edx, r12d           ; arch type
    xor r8, r8              ; VA = 0
    mov r9, rsi             ; instruction bytes
    
    lea rax, instr_result
    mov QWORD PTR [rsp+28h], rax
    
    call RawrDisasm_RISCV_Decode
    
    ; Check result (EAX = bytes consumed)
    test eax, eax
    jz @@fail
    
    ; Print OK
    lea rcx, msg_ok
    call print_cstring
    jmp @@done
    
@@fail:
    lea rcx, msg_fail
    call print_cstring
    
@@done:
    add rsp, 28h
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
test_riscv_decode ENDP

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
    mov r8d, ebx          ; nNumberOfBytesToWrite
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

; =============================================================================
; print_string - Print string with length
;   RCX = string pointer
;   EDX = length
; =============================================================================
print_string PROC FRAME
    push rbx
    push rsi
    push rdi
    .pushreg rbx
    .pushreg rsi
    .pushreg rdi
    sub rsp, 20h
    .allocstack 20h
    .endprolog

    mov rsi, rcx
    mov ebx, edx
    
    ; Write to stdout
    mov rcx, -11            ; STD_OUTPUT_HANDLE
    call GetStdHandle
    
    mov rcx, rax            ; hConsole
    mov rdx, rsi            ; lpBuffer
    mov r8d, ebx            ; nNumberOfBytesToWrite
    xor r9, r9              ; lpNumberOfBytesWritten
    mov QWORD PTR [rsp+20h], 0  ; lpOverlapped
    call WriteFile

    add rsp, 20h
    pop rdi
    pop rsi
    pop rbx
    ret
print_string ENDP

END
