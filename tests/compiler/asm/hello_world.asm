; Test: x64 Assembly Hello World
; Expected: Exit code 0

.code
main PROC
    ; Exit with code 0
    xor rax, rax
    ret
main ENDP
END
