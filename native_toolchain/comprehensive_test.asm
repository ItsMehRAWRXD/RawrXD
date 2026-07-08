; Comprehensive test of native assembler
; Tests multiple instruction types

; Register moves
mov rax, rcx
mov rdx, rbx

; Arithmetic
add rax, rdx
sub rax, rbx

; Push/pop
push rax
pop rcx

; Return
ret
