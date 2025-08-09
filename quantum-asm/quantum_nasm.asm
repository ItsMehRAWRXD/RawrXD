; NASM Assembly File for MinGW
; Compatible with both 32-bit and 64-bit targets

%ifdef WIN64
    %define IS_64BIT
%endif

section .text

; Simple test function that can be called from C++
; extern "C" int test_masm_function();
global test_masm_function
%ifndef IS_64BIT
global _test_masm_function
_test_masm_function:
%endif
test_masm_function:
    mov eax, 42             ; Return 42 as test value
    ret

; Simple function to add two numbers
; extern "C" int add_numbers(int a, int b);
global add_numbers
%ifndef IS_64BIT
global _add_numbers
_add_numbers:
%endif
add_numbers:
%ifdef IS_64BIT
    ; 64-bit calling convention (Microsoft x64)
    mov eax, ecx           ; First parameter in RCX
    add eax, edx           ; Second parameter in RDX
%else
    ; 32-bit calling convention (stdcall)
    mov eax, [esp+4]       ; First parameter
    add eax, [esp+8]       ; Second parameter
%endif
    ret

; XOR encryption function
; extern "C" void xor_encrypt(unsigned char* data, size_t length, unsigned char key);
global xor_encrypt
%ifndef IS_64BIT
global _xor_encrypt
_xor_encrypt:
%endif
xor_encrypt:
%ifdef IS_64BIT
    ; RCX = data pointer, RDX = length, R8B = key
    test rdx, rdx
    jz .done
.loop:
    xor [rcx], r8b
    inc rcx
    dec rdx
    jnz .loop
.done:
%else
    ; 32-bit version
    push ebp
    mov ebp, esp
    push esi
    push edi
    
    mov esi, [ebp+8]       ; data pointer
    mov ecx, [ebp+12]      ; length
    mov al, [ebp+16]       ; key byte
    
    test ecx, ecx
    jz .done32
.loop32:
    xor [esi], al
    inc esi
    dec ecx
    jnz .loop32
.done32:
    pop edi
    pop esi
    pop ebp
%endif
    ret