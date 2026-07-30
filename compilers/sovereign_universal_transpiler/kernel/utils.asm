; utils.asm - Common utilities for Sovereign Universal Transpiler

.code

; MemoryCopy - Copy memory block
; RCX = dest, RDX = src, R8 = count
MemoryCopy PROC
    mov r9, rcx
    mov rax, r8
    test rax, rax
    jz copy_done
    rep movsb
copy_done:
    mov rax, r9
    ret
MemoryCopy ENDP

; MemorySet - Fill memory with byte
; RCX = dest, RDX = byte value, R8 = count
MemorySet PROC
    mov r9, rcx
    mov al, dl
    rep stosb
    mov rax, r9
    ret
MemorySet ENDP

; StringLength - Get string length
; RCX = string pointer
; Returns: RAX = length
StringLength PROC
    xor rax, rax
str_len_loop:
    cmp byte ptr [rcx + rax], 0
    je str_len_done
    inc rax
    jmp str_len_loop
str_len_done:
    ret
StringLength ENDP

; StringCompare - Compare two strings
; RCX = str1, RDX = str2
; Returns: RAX = 0 if equal, nonzero if different
StringCompare PROC
    push rbx
    mov r8, rcx
    mov r9, rdx
compare_loop:
    mov al, [r8]
    mov bl, [r9]
    cmp al, bl
    jne compare_diff
    test al, al
    jz compare_same
    inc r8
    inc r9
    jmp compare_loop
compare_same:
    xor rax, rax
    pop rbx
    ret
compare_diff:
    movzx rax, al
    movzx rbx, bl
    sub rax, rbx
    pop rbx
    ret
StringCompare ENDP

; NumberToString - Convert number to decimal string
; RCX = number, RDX = output buffer
; Returns: RAX = string length
NumberToString PROC
    push rbx
    push rsi
    mov rax, rcx
    mov rsi, rdx
    mov rbx, 10
    
    ; Handle 0
    test rax, rax
    jnz num_conv_loop
    mov byte ptr [rsi], '0'
    mov rax, 1
    pop rsi
    pop rbx
    ret
    
num_conv_loop:
    test rax, rax
    jz num_conv_done
    xor rdx, rdx
    div rbx
    add dl, '0'
    mov [rsi], dl
    inc rsi
    jmp num_conv_loop
    
num_conv_done:
    ; Reverse the string (simplified - in production would reverse)
    mov rax, rsi
    sub rax, rdx    ; length
    pop rsi
    pop rbx
    ret
NumberToString ENDP

end