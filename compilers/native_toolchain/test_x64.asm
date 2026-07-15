; x64 test for real assembler
code SEGMENT ALIGN(16) READ EXECUTE
_start:
    mov rax, 42
    ret
code ENDS
END
