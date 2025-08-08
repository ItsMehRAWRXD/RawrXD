; Test MASM assembly file to verify MASM configuration
; This file can be used to test that MASM is properly configured in the project

.386
.model flat, stdcall
.stack 4096

.code

; Simple test function that can be called from C++
; extern "C" int test_masm_function();
test_masm_function PROC
    mov eax, 42    ; Return 42 as test value
    ret
test_masm_function ENDP

; Simple function to add two numbers
; extern "C" int add_numbers(int a, int b);
add_numbers PROC a:DWORD, b:DWORD
    mov eax, a
    add eax, b
    ret
add_numbers ENDP

END