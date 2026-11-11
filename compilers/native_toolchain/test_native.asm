; Test file for native assembler
; Supports x86, x64, and x32

.code

; Entry point
_start:
    ; Test basic instructions
    mov rax, 0x123456789ABCDEF0
    mov rbx, rax
    mov rcx, 0x100
    
    ; Test arithmetic
    add rax, rbx
    sub rax, rcx
    inc rax
    dec rax
    
    ; Test logical
    and rax, 0xFFFFFFFF
    or rax, rbx
    xor rax, rax
    
    ; Test shifts
    mov rax, 1
    shl rax, 4
    shr rax, 2
    
    ; Test comparisons
    cmp rax, rbx
    test rax, rax
    
    ; Test conditional moves
    cmove rax, rbx
    cmovne rcx, rdx
    
    ; Test branches
    jmp short_label
    nop
    nop
    
short_label:
    je equal_label
    jne not_equal_label
    
equal_label:
    mov rax, 1
    jmp exit_label
    
not_equal_label:
    mov rax, 2
    
exit_label:
    ; Test stack operations
    push rax
    push rbx
    pop rbx
    pop rax
    
    ; Test call/ret
    call test_proc
    
    ; Exit via syscall (Linux style, for testing)
    ; On Windows would use ExitProcess
    xor rax, rax
    ret

test_proc:
    mov rax, 42
    ret

.data
    align 8
my_data:
    .qword 0xDEADBEEFCAFEBABE
    .dword 0x12345678
    .word 0xABCD
    .byte 0xFF
    
my_string:
    .asciiz "Hello, Native Assembler!"

.rdata
    align 8
const_data:
    .qword 0x1122334455667788

.bss
    align 8
uninitialized:
    .qword 0
    .qword 0
