; utils.asm - Common utilities for Sovereign Universal Transpiler
; Production: correct register usage, no clobbered counts

option casemap:none

.code

; MemoryCopy - Copy memory block
; RCX = dest, RDX = src, R8 = count
; Returns: RAX = dest (original)
; Preserves: none (volatile per Win64 ABI)
MemoryCopy PROC
    push rdi
    push rsi
    
    mov r9, rcx            ; save dest for return
    mov rdi, rcx           ; dest for rep movsb
    mov rsi, rdx           ; src for rep movsb
    mov rcx, r8            ; count for rep movsb
    test rcx, rcx
    jz copy_done
    rep movsb
copy_done:
    mov rax, r9            ; return original dest
    
    pop rsi
    pop rdi
    ret
MemoryCopy ENDP

; MemorySet - Fill memory with byte
; RCX = dest, RDX = byte value, R8 = count
; Returns: RAX = dest (original)
MemorySet PROC
    push rdi
    
    mov r9, rcx            ; save dest for return
    mov rdi, rcx           ; dest for rep stosb
    mov al, dl             ; byte value
    mov rcx, r8            ; count
    test rcx, rcx
    jz set_done
    rep stosb
set_done:
    mov rax, r9            ; return original dest
    
    pop rdi
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

; NumberToString - Convert unsigned 64-bit number to decimal string
; RCX = number, RDX = output buffer (at least 21 bytes)
; Returns: RAX = string length (not including null terminator)
; Output is null-terminated
NumberToString PROC
    push rbx
    push rsi
    push rdi
    
    mov rax, rcx            ; number
    mov rsi, rdx            ; output buffer
    mov rdi, rdx            ; save start
    mov rbx, 10             ; divisor
    
    ; Handle 0 specially
    test rax, rax
    jnz num_conv_loop
    mov byte ptr [rsi], '0'
    mov byte ptr [rsi + 1], 0
    mov rax, 1
    jmp num_done
    
num_conv_loop:
    test rax, rax
    jz num_reverse
    xor rdx, rdx
    div rbx                 ; RDX:RAX / 10 -> RAX=quotient, RDX=remainder
    add dl, '0'
    mov [rsi], dl           ; store digit (LSB first)
    inc rsi
    jmp num_conv_loop
    
num_reverse:
    ; Null-terminate
    mov byte ptr [rsi], 0
    
    ; Calculate length
    mov rcx, rsi
    sub rcx, rdi            ; length = end - start
    
    ; Reverse the string in-place
    ; rdi = start, rsi = end (one past last char)
    dec rsi                 ; rsi = last char
rev_loop:
    cmp rdi, rsi
    jge rev_done
    mov al, [rdi]
    mov bl, [rsi]
    mov [rdi], bl
    mov [rsi], al
    inc rdi
    dec rsi
    jmp rev_loop
rev_done:
    
    mov rax, rcx            ; return length
    
num_done:
    pop rdi
    pop rsi
    pop rbx
    ret
NumberToString ENDP

end