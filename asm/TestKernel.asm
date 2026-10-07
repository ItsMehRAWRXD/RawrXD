; TestKernel.asm - Minimal MASM64 kernel for testing
; Assemble: ml64.exe /c /Fo TestKernel.obj TestKernel.asm

.code

; Simple add kernel: output[i] = input[i] + 1.0
TestKernel_AddOne PROC FRAME
    ; RCX = input pointer
    ; RDX = output pointer  
    ; R8 = count
    
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    .endprolog
    
    mov rsi, rcx        ; RSI = input
    mov rdi, rdx        ; RDI = output
    mov rcx, r8         ; RCX = count
    
    test rcx, rcx
    jz done
    
loop_start:
    movss xmm0, dword ptr [rsi]
    addss xmm0, dword ptr [one]
    movss dword ptr [rdi], xmm0
    
    add rsi, 4
    add rdi, 4
    dec rcx
    jnz loop_start
    
done:
    pop rdi
    pop rsi
    pop rbx
    ret
    
    align 16
one:
    real4 1.0
    
TestKernel_AddOne ENDP

; Export marker
PUBLIC TestKernel_AddOne

END
