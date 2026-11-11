;=============================================================================
; test_backend.asm - Test for Language Backend Generator
; Native x64 Assembly for RawrXD Toolchain
;=============================================================================

.text

; Entry point
_start:
    sub     rsp, 40
    lea     rcx, [message]
    call    print_string
    mov     rax, 42
    add     rsp, 40
    ret

; Print string function
print_string:
    sub     rsp, 40
    mov     rdx, rcx
    mov     r8, 50
    lea     r9, [rsp + 32]
    mov     qword ptr [rsp + 32], 0
    mov     rcx, -11
    call    GetStdHandle
    mov     rcx, rax
    mov     rdx, rdx
    mov     r8, r8
    lea     r9, [rsp + 32]
    mov     qword ptr [rsp + 32], 0
    call    WriteFile
    add     rsp, 40
    ret

.data

message:
    db 'Hello from RawrXD Native Toolchain!', 0Dh, 0Ah, 0

counter:
    dq 0

result:
    dq 0