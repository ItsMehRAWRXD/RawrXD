; Test data section with RIP-relative addressing
.text

main:
    ; Load address of counter into rax
    lea rax, [counter]
    
    ; Load value from counter into rcx
    mov rcx, [counter]
    
    ; Increment the counter
    inc rcx
    
    ; Store back to counter
    mov [counter], rcx
    
    ; Load message address
    lea rdx, [message]
    
    ; Return 0
    xor eax, eax
    ret

.data
counter:
    dq 42

message:
    db "Hello, World!", 0
