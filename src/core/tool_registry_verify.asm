; ============================================================================
; tool_registry_verify.asm — Simple verification of Tool Registry
; ============================================================================

extern GetStdHandle:proc
extern WriteConsoleA:proc
extern ExitProcess:proc
extern Tool_Execute:proc

; Status codes
STATUS_SUCCESS          equ 0
STATUS_INVALID_OPCODE   equ 1
STATUS_INVALID_ARGUMENT equ 2

; Tool opcodes
TOOL_NOP                equ 00h
TOOL_SYS_TIME           equ 06h
TOOL_SYS_SLEEP          equ 07h

.data

msg_start               db "=== Tool Registry Verification ===", 13, 10, 0
msg_test1               db "Test 1 - NOP: ", 0
msg_test2               db "Test 2 - TIME: ", 0
msg_test3               db "Test 3 - SLEEP: ", 0
msg_test4               db "Test 4 - INVALID: ", 0
msg_pass                db "PASS", 13, 10, 0
msg_fail                db "FAIL (code: ", 0
msg_close               db ")", 13, 10, 0
msg_summary             db "=== Summary ===", 13, 10, 0
msg_passed              db "Tests passed: ", 0
msg_slash               db " / ", 0
msg_newline             db 13, 10, 0

test_buffer             db 256 dup(0)
pass_count              dq 0
total_count             dq 4
stdout_handle           dq 0

.code

PrintString proc
    push rbx
    push rdi
    sub rsp, 40
    
    mov rdi, rcx
    xor rbx, rbx
@@count:
    mov al, [rdi+rbx]
    test al, al
    jz @@print
    inc rbx
    jmp @@count
@@print:
    mov rax, [stdout_handle]
    test rax, rax
    jnz @@write
    mov rcx, -11
    call GetStdHandle
    mov [stdout_handle], rax
@@write:
    mov rcx, [stdout_handle]
    mov rdx, rdi
    mov r8, rbx
    xor r9, r9
    mov qword ptr [rsp+32], 0
    call WriteConsoleA
    add rsp, 40
    pop rdi
    pop rbx
    ret
PrintString endp

PrintNumber proc
    push rbx
    push rdi
    sub rsp, 56
    mov rax, rcx
    lea rdi, [rsp+32]
    mov rcx, 20
    mov byte ptr [rdi+rcx], 0
    mov rbx, 10
@@convert:
    xor rdx, rdx
    div rbx
    add dl, '0'
    dec rcx
    mov [rdi+rcx], dl
    test rax, rax
    jnz @@convert
    lea rcx, [rdi+rcx]
    call PrintString
    add rsp, 56
    pop rdi
    pop rbx
    ret
PrintNumber endp

RunTest proc
    push rbx
    push r12
    sub rsp, 40
    
    mov r12, rax              ; Save expected result
    
    ; Call Tool_Execute
    call Tool_Execute
    
    ; Check result
    cmp rax, r12
    je @@pass
    
    ; Fail
    lea rcx, [msg_fail]
    call PrintString
    mov rcx, rax
    call PrintNumber
    lea rcx, [msg_close]
    call PrintString
    jmp @@done
    
@@pass:
    lea rcx, [msg_pass]
    call PrintString
    inc qword ptr [pass_count]
    
@@done:
    add rsp, 40
    pop r12
    pop rbx
    ret
RunTest endp

main proc
    sub rsp, 40
    
    lea rcx, [msg_start]
    call PrintString
    
    ; Test 1: NOP
    lea rcx, [msg_test1]
    call PrintString
    mov rcx, TOOL_NOP
    xor rdx, rdx
    xor r8, r8
    xor r9, r9
    mov rax, STATUS_SUCCESS
    call RunTest
    
    ; Test 2: SYS_TIME with valid buffer
    lea rcx, [msg_test2]
    call PrintString
    mov rcx, TOOL_SYS_TIME
    lea rdx, [test_buffer]
    xor r8, r8
    xor r9, r9
    mov rax, STATUS_SUCCESS
    call RunTest
    
    ; Test 3: SYS_SLEEP valid
    lea rcx, [msg_test3]
    call PrintString
    mov rcx, TOOL_SYS_SLEEP
    mov rdx, 1                ; 1ms
    xor r8, r8
    xor r9, r9
    mov rax, STATUS_SUCCESS
    call RunTest
    
    ; Test 4: Invalid opcode
    lea rcx, [msg_test4]
    call PrintString
    mov rcx, 0FEh             ; Invalid
    xor rdx, rdx
    xor r8, r8
    xor r9, r9
    mov rax, STATUS_INVALID_OPCODE
    call RunTest
    
    ; Summary
    lea rcx, [msg_newline]
    call PrintString
    lea rcx, [msg_summary]
    call PrintString
    lea rcx, [msg_passed]
    call PrintString
    mov rcx, [pass_count]
    call PrintNumber
    lea rcx, [msg_slash]
    call PrintString
    mov rcx, [total_count]
    call PrintNumber
    lea rcx, [msg_newline]
    call PrintString
    
    xor ecx, ecx
    call ExitProcess
main endp

end
