# MinGW/GAS Assembly File
# Compatible with x86_64-w64-mingw32-as and i686-w64-mingw32-as

.intel_syntax noprefix      # Use Intel syntax (similar to MASM)

# For 32-bit builds
.ifdef X86_32
    .code32
.endif

.section .text

# Simple test function that can be called from C++
# extern "C" int test_masm_function();
.global test_masm_function
.global _test_masm_function    # MinGW on Windows needs underscore for 32-bit
test_masm_function:
_test_masm_function:
    mov eax, 42             # Return 42 as test value
    ret

# Simple function to add two numbers
# extern "C" int add_numbers(int a, int b);
.global add_numbers
.global _add_numbers       # MinGW on Windows needs underscore for 32-bit
add_numbers:
_add_numbers:
.ifdef X86_32
    # 32-bit calling convention (stdcall)
    mov eax, [esp+4]       # First parameter
    add eax, [esp+8]       # Second parameter
.else
    # 64-bit calling convention (Microsoft x64)
    mov eax, ecx           # First parameter in RCX
    add eax, edx           # Second parameter in RDX
.endif
    ret

# Additional quantum-related functions can go here
# Example: XOR encryption function
.global xor_encrypt
.global _xor_encrypt
xor_encrypt:
_xor_encrypt:
.ifdef X86_32
    push ebp
    mov ebp, esp
    mov ecx, [ebp+8]       # data pointer
    mov edx, [ebp+12]      # length
    mov al, [ebp+16]       # key byte
.L1:
    test edx, edx
    jz .L2
    xor [ecx], al
    inc ecx
    dec edx
    jmp .L1
.L2:
    pop ebp
.else
    # RCX = data pointer, RDX = length, R8B = key
    test rdx, rdx
    jz .L3
.L4:
    xor [rcx], r8b
    inc rcx
    dec rdx
    jnz .L4
.L3:
.endif
    ret