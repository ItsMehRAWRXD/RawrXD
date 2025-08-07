; test_masm_x64.asm - 64-bit MASM test file
; This file demonstrates MASM is properly configured for x64

.code

; Simple function that adds two numbers
; extern "C" int AddNumbers(int a, int b);
AddNumbers PROC
    mov eax, ecx        ; First parameter in RCX (lower 32 bits)
    add eax, edx        ; Add second parameter in RDX (lower 32 bits)
    ret                 ; Return result in RAX (lower 32 bits)
AddNumbers ENDP

END