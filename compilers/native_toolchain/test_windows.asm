; test_windows.asm - Windows executable test
; Tests native toolchain with Windows API calls

.code

; Entry point
main:
    ; Exit with code 0
    xor rcx, rcx        ; Exit code 0
    mov rax, 0          ; Placeholder for ExitProcess
    
    ; Return to caller
    ret

.data
    ; Data section
message:
    .byte 'H', 'e', 'l', 'l', 'o', 0

.rdata
    ; Read-only data
const_value:
    .qword 0x123456789ABCDEF0

.bss
    ; Uninitialized data
buffer:
    .qword 0