; launcher_minimal.asm - Minimal launcher using native toolchain
; Just calls ExitProcess(0)

.text
main:
    sub rsp, 40
    xor rcx, rcx
    call ExitProcess
