; test_masm.asm - Simple MASM test file
; This file demonstrates MASM is properly configured

.686
.model flat, C

.code

; Simple function that adds two numbers
; extern "C" int AddNumbers(int a, int b);
AddNumbers PROC
    mov eax, [esp+4]    ; Get first parameter
    add eax, [esp+8]    ; Add second parameter
    ret                 ; Return result in EAX
AddNumbers ENDP

END