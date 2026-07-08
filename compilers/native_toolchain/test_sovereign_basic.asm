; test_sovereign_basic.asm - Test basic Sovereign operations
; Pure x64 MASM - tests core functionality without heap initialization
; Build: ml64 /c test_sovereign_basic.asm && link /subsystem:console /entry:Start test_sovereign_basic.obj kernel32.lib

EXTERN GetStdHandle:PROC
EXTERN WriteFile:PROC
EXTERN ExitProcess:PROC

.data
    ; Test messages
    msg_start db '=== Sovereign Basic Test ===', 13, 10, 0
    msg_start_len equ $ - msg_start
    
    msg_stdout db 'Test 1: GetStdHandle - ', 0
    msg_stdout_len equ $ - msg_stdout
    
    msg_write db 'Test 2: WriteFile - ', 0
    msg_write_len equ $ - msg_write
    
    msg_pass db 'PASS', 13, 10, 0
    msg_pass_len equ $ - msg_pass
    
    msg_fail db 'FAIL', 13, 10, 0
    msg_fail_len equ $ - msg_fail
    
    msg_complete db '=== All Tests Complete ===', 13, 10, 0
    msg_complete_len equ $ - msg_complete
    
    newline db 13, 10, 0
    newline_len equ $ - newline
    
    ; Test data
    test_buffer db 'Test buffer data', 0
    test_buffer_len equ $ - test_buffer
    
    ; Results
    tests_passed dd 0
    tests_failed dd 0

.code
Start PROC
    sub rsp, 56                 ; Shadow space + alignment
    
    ; Print header
    lea rdx, msg_start
    mov r8, msg_start_len
    call PrintString
    
    ; Test 1: GetStdHandle
    lea rdx, msg_stdout
    mov r8, msg_stdout_len
    call PrintString
    
    mov ecx, -11                ; STD_OUTPUT_HANDLE
    call GetStdHandle
    mov r12, rax                ; Save stdout handle
    
    test rax, rax
    jz test1_fail
    
    ; GetStdHandle passed
    lea rdx, msg_pass
    mov r8, msg_pass_len
    call PrintString
    inc dword ptr [tests_passed]
    jmp test2
    
test1_fail:
    lea rdx, msg_fail
    mov r8, msg_fail_len
    call PrintString
    inc dword ptr [tests_failed]

test2:
    ; Test 2: WriteFile
    lea rdx, msg_write
    mov r8, msg_write_len
    call PrintString
    
    ; Try to write using the handle from test 1
    mov rcx, r12                ; hConsoleOutput
    lea rdx, test_buffer        ; lpBuffer
    mov r8, test_buffer_len     ; nNumberOfCharsToWrite
    xor r9, r9                  ; lpNumberOfCharsWritten (optional)
    mov qword ptr [rsp+32], 0   ; lpReserved
    call WriteFile
    
    test rax, rax
    jz test2_fail
    
    ; WriteFile passed
    call PrintNewline
    lea rdx, msg_pass
    mov r8, msg_pass_len
    call PrintString
    inc dword ptr [tests_passed]
    jmp test3
    
test2_fail:
    lea rdx, msg_fail
    mov r8, msg_fail_len
    call PrintString
    inc dword ptr [tests_failed]

test3:
    ; Test 3: Basic arithmetic
    mov rax, 12345678h
    add rax, 87654321h
    sub rax, 99999999h
    
    ; Result should be 0
    test rax, rax
    jnz test3_fail
    
    ; Arithmetic test passed
    inc dword ptr [tests_passed]
    jmp test4
    
test3_fail:
    inc dword ptr [tests_failed]

test4:
    ; Test 4: Memory operations (stack only, no heap)
    sub rsp, 256                ; Allocate stack space
    
    ; Write pattern to stack
    mov rcx, 64                 ; 64 qwords = 512 bytes
    mov rdi, rsp
    mov rax, 0DEADBEEFCAFEBABEh
write_loop:
    mov [rdi], rax
    add rdi, 8
    dec rcx
    jnz write_loop
    
    ; Verify pattern
    mov rcx, 64
    mov rdi, rsp
    mov rax, 0DEADBEEFCAFEBABEh
verify_loop:
    mov rbx, [rdi]
    cmp rbx, rax
    jne test4_fail
    add rdi, 8
    dec rcx
    jnz verify_loop
    
    ; Memory test passed
    add rsp, 256                ; Restore stack
    inc dword ptr [tests_passed]
    jmp test_complete
    
test4_fail:
    add rsp, 256                ; Restore stack
    inc dword ptr [tests_failed]

test_complete:
    ; Print completion message
    call PrintNewline
    lea rdx, msg_complete
    mov r8, msg_complete_len
    call PrintString
    
    ; Print summary
    ; (In a real implementation, convert numbers to strings)
    
    ; Exit with code based on results
    mov ecx, 0
    cmp dword ptr [tests_failed], 0
    je exit_clean
    mov ecx, 1
    
exit_clean:
    call ExitProcess
    
    add rsp, 56
    ret
Start ENDP

; PrintString - Helper to print a string
; RDX = string pointer
; R8 = string length
PrintString PROC
    push rbx
    push r12
    push r13
    
    mov r12, rdx                ; Save string pointer
    mov r13, r8                 ; Save length
    
    ; Get stdout handle
    mov ecx, -11
    call GetStdHandle
    mov rbx, rax                ; Save handle
    
    ; Write string
    mov rcx, rbx                ; hConsoleOutput
    mov rdx, r12                ; lpBuffer
    mov r8, r13                 ; nNumberOfCharsToWrite
    xor r9, r9                  ; lpNumberOfCharsWritten
    mov qword ptr [rsp+32], 0   ; lpReserved
    call WriteFile
    
    pop r13
    pop r12
    pop rbx
    ret
PrintString ENDP

; PrintNewline - Helper to print newline
PrintNewline PROC
    push rbx
    push r12
    
    mov r12, rdx                ; Save RDX
    
    ; Get stdout handle
    mov ecx, -11
    call GetStdHandle
    mov rbx, rax
    
    ; Write newline
    mov rcx, rbx
    lea rdx, newline
    mov r8, newline_len
    xor r9, r9
    mov qword ptr [rsp+32], 0
    call WriteFile
    
    mov rdx, r12                ; Restore RDX
    pop r12
    pop rbx
    ret
PrintNewline ENDP

END
