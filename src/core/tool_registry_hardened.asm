; ============================================================================
; tool_registry_hardened.asm — Hardened Tool Registry with ABI Validation
; ============================================================================
;
; Provides a syscall-like interface with comprehensive validation.
; Register-based ABI: RCX = opcode, RDX = arg1, R8 = arg2, R9 = arg3
; All nonvolatile registers preserved per Win64 ABI.
;
; Build: ml64.exe /c tool_registry_hardened.asm
; Link:  link.exe tool_registry_hardened.obj [other objs] /OUT:Test.exe
;
; ============================================================================

; ============================================================================
; External Imports (Windows API)
; ============================================================================

extern GetStdHandle:proc
extern WriteConsoleA:proc
extern GetSystemTime:proc
extern Sleep:proc
extern GetCurrentDirectoryA:proc
extern ExitProcess:proc

; ============================================================================
; Constants
; ============================================================================

; Tool opcodes (Action ABI)
TOOL_NOP                equ 00h
TOOL_FILE_READ          equ 01h
TOOL_FILE_WRITE         equ 02h
TOOL_FILE_SIZE          equ 03h
TOOL_DIR_LIST           equ 04h
TOOL_DIR_CWD            equ 05h
TOOL_SYS_TIME           equ 06h
TOOL_SYS_SLEEP          equ 07h
TOOL_SYS_EXIT           equ 0FFh
TOOL_MAX_OPCODE         equ 07h     ; Highest valid opcode

; Status codes (uniform)
STATUS_SUCCESS          equ 0
STATUS_INVALID_OPCODE   equ 1
STATUS_INVALID_ARGUMENT equ 2
STATUS_ACCESS_DENIED    equ 3
STATUS_IO_ERROR         equ 4
STATUS_INTERNAL_ERROR   equ 5
STATUS_BUFFER_TOO_SMALL equ 6

; Validation constants
MAX_SLEEP_MS            equ 3600000 ; 1 hour max
MIN_BUFFER_SIZE         equ 16      ; Minimum buffer for time/cwd

; ============================================================================
; Data Section
; ============================================================================

.data

; Test counters for validation
test_call_count         dq 0
test_success_count      dq 0
test_fail_count         dq 0

; Status message strings
msg_status_success      db " [SUCCESS]", 13, 10, 0
msg_status_invalid_op   db " [INVALID_OPCODE]", 13, 10, 0
msg_status_invalid_arg  db " [INVALID_ARGUMENT]", 13, 10, 0
msg_status_io_error     db " [IO_ERROR]", 13, 10, 0
msg_status_internal     db " [INTERNAL_ERROR]", 13, 10, 0

; Test messages
msg_test_start          db "=== Tool Registry Tests ===", 13, 10, 0
msg_test_pass           db "PASS: ", 0
msg_test_fail           db "FAIL: ", 0
msg_test_summary        db "=== Test Summary ===", 13, 10, 0
msg_test_total          db "Total: ", 0
msg_test_passed         db "Passed: ", 0
msg_test_failed         db "Failed: ", 0
msg_newline             db 13, 10, 0

; Console handle
stdout_handle           dq 0

; ============================================================================
; Code Section
; ============================================================================

.code

; ============================================================================
; Console Output Helpers
; ============================================================================

; void PrintString(const char* str)
; RCX = string pointer
PrintString proc
    push rbx
    push rdi
    push rsi
    sub rsp, 40
    
    mov rdi, rcx
    xor rbx, rbx
    
@@count:
    mov al, [rdi + rbx]
    test al, al
    jz @@print
    inc rbx
    jmp @@count
    
@@print:
    test rbx, rbx
    jz @@done
    
    mov rax, [stdout_handle]
    test rax, rax
    jnz @@write
    
    mov rcx, -11              ; STD_OUTPUT_HANDLE
    call GetStdHandle
    mov [stdout_handle], rax
    
@@write:
    mov rcx, [stdout_handle]
    mov rdx, rdi
    mov r8, rbx
    xor r9, r9
    mov qword ptr [rsp+32], 0
    call WriteConsoleA
    
@@done:
    add rsp, 40
    pop rsi
    pop rdi
    pop rbx
    ret
PrintString endp

; void PrintNumber(uint64_t num)
; RCX = number to print
PrintNumber proc
    push rbx
    push rdi
    push rsi
    sub rsp, 56               ; +16 for alignment
    
    mov rax, rcx
    lea rdi, [rsp+32]         ; Buffer on stack
    mov rcx, 20               ; Max digits
    mov byte ptr [rdi+rcx], 0 ; Null terminator
    
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
    pop rsi
    pop rdi
    pop rbx
    ret
PrintNumber endp

; ============================================================================
; Tool Implementations (All preserve nonvolatile registers)
; ============================================================================

; Tool_Nop_Impl — No operation
; Returns: STATUS_SUCCESS
; Preserves: All nonvolatile registers
Tool_Nop_Impl proc
    push rbx
    push rbp
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8                ; Maintain 16-byte alignment
    
    mov rax, STATUS_SUCCESS
    
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    ret
Tool_Nop_Impl endp

; Tool_SystemTime — Get system time
; RCX = buffer (must be at least 16 bytes)
; Returns: STATUS_SUCCESS or STATUS_INVALID_ARGUMENT
Tool_SystemTime proc
    push rbx
    push rbp
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub rsp, 40
    
    ; Validate buffer pointer
    mov rbx, rcx              ; Save buffer pointer
    test rbx, rbx
    jz @@invalid_arg
    
    ; Validate buffer alignment (must be 8-byte aligned)
    test bl, 7
    jnz @@invalid_arg
    
    ; Call Windows API
    mov rcx, rbx
    call GetSystemTime
    
    mov rax, STATUS_SUCCESS
    jmp @@done
    
@@invalid_arg:
    mov rax, STATUS_INVALID_ARGUMENT
    
@@done:
    add rsp, 40
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    ret
Tool_SystemTime endp

; Tool_Sleep — Sleep for specified milliseconds
; RCX = milliseconds (0 to MAX_SLEEP_MS)
; Returns: STATUS_SUCCESS or STATUS_INVALID_ARGUMENT
Tool_Sleep proc
    push rbx
    push rbp
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub rsp, 40
    
    ; Validate sleep duration
    mov rbx, rcx
    cmp rbx, MAX_SLEEP_MS
    ja @@invalid_arg
    
    ; Call Windows API
    mov ecx, ebx
    call Sleep
    
    mov rax, STATUS_SUCCESS
    jmp @@done
    
@@invalid_arg:
    mov rax, STATUS_INVALID_ARGUMENT
    
@@done:
    add rsp, 40
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    ret
Tool_Sleep endp

; Tool_GetCWD — Get current working directory
; RCX = buffer, RDX = buffer size
; Returns: STATUS_SUCCESS, STATUS_INVALID_ARGUMENT, or STATUS_BUFFER_TOO_SMALL
Tool_GetCWD proc
    push rbx
    push rbp
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub rsp, 40
    
    ; Validate arguments
    mov rbx, rcx              ; Buffer
    mov r12, rdx              ; Buffer size
    test rbx, rbx
    jz @@invalid_arg
    test r12, r12
    jz @@invalid_arg
    cmp r12, MIN_BUFFER_SIZE
    jb @@buffer_too_small
    
    ; Call Windows API
    ; GetCurrentDirectoryA(nBufferLength, lpBuffer)
    ; RCX = nBufferLength (DWORD), RDX = lpBuffer
    mov rdx, rbx              ; Buffer pointer
    mov ecx, r12d             ; Buffer size (DWORD)
    call GetCurrentDirectoryA
    
    test rax, rax
    jz @@io_error
    
    mov rax, STATUS_SUCCESS
    jmp @@done
    
@@invalid_arg:
    mov rax, STATUS_INVALID_ARGUMENT
    jmp @@done
    
@@buffer_too_small:
    mov rax, STATUS_BUFFER_TOO_SMALL
    jmp @@done
    
@@io_error:
    mov rax, STATUS_IO_ERROR
    
@@done:
    add rsp, 40
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    ret
Tool_GetCWD endp

; ============================================================================
; Hardened Tool Dispatcher
; ============================================================================

; int Tool_Execute(uint64_t opcode, void* arg1, void* arg2, void* arg3)
; RCX = opcode, RDX = arg1, R8 = arg2, R9 = arg3
; Returns: RAX = status code
; Preserves: RBX, RBP, RSI, RDI, R12-R15
Tool_Execute proc
    push rbx
    push rbp
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub rsp, 40
    
    ; Save arguments
    mov r12, rcx              ; opcode
    mov r13, rdx              ; arg1
    mov r14, r8               ; arg2
    mov r15, r9               ; arg3
    
    ; Increment call counter
    inc qword ptr [test_call_count]
    
    ; Validate opcode range
    cmp r12b, TOOL_MAX_OPCODE
    ja @@check_special
    
    ; Dispatch based on opcode using switch
    movzx eax, r12b
    cmp eax, 0
    je @@do_nop
    cmp eax, 5
    je @@do_getcwd
    cmp eax, 6
    je @@do_time
    cmp eax, 7
    je @@do_sleep
    jmp @@unimplemented
    
@@check_special:
    cmp r12b, TOOL_SYS_EXIT
    je @@do_exit
    jmp @@invalid_opcode
    
@@do_nop:
    call Tool_Nop_Impl
    jmp @@done
    
@@do_time:
    mov rcx, r13              ; arg1 = buffer
    call Tool_SystemTime
    jmp @@done
    
@@do_sleep:
    mov rcx, r13              ; arg1 = milliseconds
    call Tool_Sleep
    jmp @@done
    
@@do_getcwd:
    mov rcx, r13              ; arg1 = buffer
    mov rdx, r14              ; arg2 = buffer size
    call Tool_GetCWD
    jmp @@done
    
@@do_exit:
    mov ecx, r13d             ; arg1 = exit code
    call ExitProcess
    ; Does not return
    
@@unimplemented:
    mov rax, STATUS_INTERNAL_ERROR
    jmp @@done
    
@@invalid_opcode:
    mov rax, STATUS_INVALID_OPCODE
    
@@done:
    ; Check if success
    cmp rax, STATUS_SUCCESS
    jne @@failure
    inc qword ptr [test_success_count]
    jmp @@return
    
@@failure:
    inc qword ptr [test_fail_count]
    
@@return:
    add rsp, 40
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    ret
Tool_Execute endp

; ============================================================================
; Test Harness
; ============================================================================

; void Test_Opcode(uint64_t opcode, const char* name, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t expected)
Test_Opcode proc
    push rbx
    push rbp
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub rsp, 40
    
    mov r12, rcx              ; opcode
    mov r13, rdx              ; name
    mov r14, r8               ; arg1
    mov r15, r9               ; arg2
    mov rbx, [rsp+128]        ; arg3 (stack) - 8 pushes + 40 shadow + 8 ret addr + 8 arg3
    mov rbp, [rsp+136]        ; expected (stack)
    
    ; Print test name
    mov rcx, r13
    call PrintString
    
    ; Call Tool_Execute
    mov rcx, r12
    mov rdx, r14
    mov r8, r15
    mov r9, rbx
    call Tool_Execute
    
    ; Debug: Print actual vs expected
    push rax
    push rbp
    lea rcx, [msg_debug_expected]
    call PrintString
    mov rcx, rbp
    call PrintNumber
    lea rcx, [msg_debug_actual]
    call PrintString
    pop rcx
    call PrintNumber
    push rcx
    
    ; Check result
    pop rbp
    pop rax
    cmp rax, rbp
    je @@pass
    
    ; Fail
    lea rcx, [msg_test_fail]
    call PrintString
    jmp @@print_result
    
@@pass:
    lea rcx, [msg_test_pass]
    call PrintString
    
@@print_result:
    ; Print status code
    mov rcx, rax
    call PrintNumber
    ; Print newline
    lea rcx, [msg_newline]
    call PrintString
    
    add rsp, 40
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    ret 16                    ; Clean up 2 stack arguments
Test_Opcode endp

; void Run_All_Tests()
Run_All_Tests proc
    push rbx
    push rbp
    push rsi
    push rdi
    sub rsp, 40
    
    ; Print header
    lea rcx, [msg_test_start]
    call PrintString
    
    ; Reset counters
    mov qword ptr [test_call_count], 0
    mov qword ptr [test_success_count], 0
    mov qword ptr [test_fail_count], 0
    
    ; Test 1: NOP
    mov rcx, TOOL_NOP
    lea rdx, [test_name_nop]
    xor r8, r8
    xor r9, r9
    push 0                    ; arg3
    push STATUS_SUCCESS       ; expected
    call Test_Opcode
    add rsp, 16
    
    ; Test 2: SYS_TIME with valid buffer
    mov rcx, TOOL_SYS_TIME
    lea rdx, [test_name_time]
    lea r8, [test_buffer]
    xor r9, r9
    push 0
    push STATUS_SUCCESS
    call Test_Opcode
    add rsp, 16
    
    ; Test 3: SYS_TIME with null buffer
    mov rcx, TOOL_SYS_TIME
    lea rdx, [test_name_time_null]
    xor r8, r8
    xor r9, r9
    push 0
    push STATUS_INVALID_ARGUMENT
    call Test_Opcode
    add rsp, 16
    
    ; Test 4: SYS_SLEEP valid
    mov rcx, TOOL_SYS_SLEEP
    lea rdx, [test_name_sleep]
    mov r8, 1                 ; 1ms
    xor r9, r9
    push 0
    push STATUS_SUCCESS
    call Test_Opcode
    add rsp, 16
    
    ; Test 5: SYS_SLEEP too large
    mov rcx, TOOL_SYS_SLEEP
    lea rdx, [test_name_sleep_large]
    mov r8, MAX_SLEEP_MS + 1
    xor r9, r9
    push 0
    push STATUS_INVALID_ARGUMENT
    call Test_Opcode
    add rsp, 16
    
    ; Test 6: Invalid opcode
    mov rcx, 0FEh
    lea rdx, [test_name_invalid]
    xor r8, r8
    xor r9, r9
    push 0
    push STATUS_INVALID_OPCODE
    call Test_Opcode
    add rsp, 16
    
    ; Test 7: DIR_CWD with valid buffer
    mov rcx, TOOL_DIR_CWD
    lea rdx, [test_name_cwd]
    lea r8, [test_buffer]
    mov r9, 4096
    push 0
    push STATUS_SUCCESS
    call Test_Opcode
    add rsp, 16
    
    ; Test 8: DIR_CWD with small buffer
    mov rcx, TOOL_DIR_CWD
    lea rdx, [test_name_cwd_small]
    lea r8, [test_buffer]
    mov r9, 4                 ; Too small
    push 0
    push STATUS_BUFFER_TOO_SMALL
    call Test_Opcode
    add rsp, 16
    
    ; Print summary
    lea rcx, [msg_test_summary]
    call PrintString
    
    lea rcx, [msg_test_total]
    call PrintString
    mov rcx, [test_call_count]
    call PrintNumber
    lea rcx, [msg_newline]
    call PrintString
    
    lea rcx, [msg_test_passed]
    call PrintString
    mov rcx, [test_success_count]
    call PrintNumber
    lea rcx, [msg_newline]
    call PrintString
    
    lea rcx, [msg_test_failed]
    call PrintString
    mov rcx, [test_fail_count]
    call PrintNumber
    lea rcx, [msg_newline]
    call PrintString
    
    add rsp, 40
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    ret
Run_All_Tests endp

; ============================================================================
; Stress Test
; ============================================================================

; void Stress_Test(uint64_t iterations)
Stress_Test proc
    push rbx
    push rbp
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub rsp, 40
    
    mov r12, rcx              ; iteration count
    xor r13, r13              ; success count
    xor r14, r14              ; current iteration
    
@@loop:
    cmp r14, r12
    jge @@done
    
    ; Test NOP
    mov rcx, TOOL_NOP
    xor rdx, rdx
    xor r8, r8
    xor r9, r9
    call Tool_Execute
    cmp rax, STATUS_SUCCESS
    jne @@fail
    inc r13
    
@@fail:
    inc r14
    jmp @@loop
    
@@done:
    mov rax, r13              ; Return success count
    
    add rsp, 40
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    ret
Stress_Test endp

; ============================================================================
; Data Section (Test Data)
; ============================================================================

.data

; Test buffers
ALIGN 16
test_buffer             db 4096 dup(0)

; Test names
test_name_nop           db "Test NOP: ", 0
test_name_time          db "Test SYS_TIME valid: ", 0
test_name_time_null     db "Test SYS_TIME null: ", 0
test_name_sleep         db "Test SYS_SLEEP valid: ", 0
test_name_sleep_large   db "Test SYS_SLEEP large: ", 0
test_name_invalid       db "Test invalid opcode: ", 0
test_name_cwd           db "Test DIR_CWD valid: ", 0
test_name_cwd_small     db "Test DIR_CWD small: ", 0

; ============================================================================
; Entry Point
; ============================================================================

.code

main proc
    sub rsp, 40
    
    ; Run comprehensive tests
    call Run_All_Tests
    
    ; Run stress test (100,000 iterations)
    mov rcx, 100000
    call Stress_Test
    
    ; Print stress test result
    lea rcx, [msg_stress_result]
    call PrintString
    mov rcx, rax
    call PrintNumber
    
    xor ecx, ecx
    call ExitProcess
    
main endp

.data
msg_stress_result       db "Stress test successes: ", 0

end
