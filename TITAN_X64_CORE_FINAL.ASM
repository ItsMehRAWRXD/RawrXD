.CODE
KERNEL_Q4_K_BLOCK PROC FRAME
    mov rax, r8
    lea rbx, [rax + rax*8]
    add rbx, rbx
    add rbx, rdx
    mov rsi, rdx
.q4_l: cmp rsi, rbx
    jae .q4_d
    vmovups xmm0, [rsi + 2]
    add rsi, 18
    jmp .q4_l
.q4_d: ret
KERNEL_Q4_K_BLOCK ENDP

KERNEL_Q5_K_BLOCK PROC FRAME
    mov rax, r8
    lea rbx, [rax + rax*8]
    shl rbx, 4
    lea rbx, [rbx + rax*32]
    add rbx, rdx
    mov rsi, rdx
.q5_l: cmp rsi, rbx
    jae .q5_d
    vmovups xmm0, [rsi]
    vmovups xmm1, [rsi + 16]
    add rsi, 176
    jmp .q5_l
.q5_d: ret
KERNEL_Q5_K_BLOCK ENDP

KERNEL_SIMD_TAILED PROC FRAME
    sub rsp, 28h
    lea rbx, [rcx + r8*4]
    mov rsi, rcx
    mov rdi, rdx
    lea rax, [rbx - 16]
.v_l: cmp rsi, rax
    jae .s_l
    vmovups xmm0, [rsi]
    vmulps xmm0, xmm0, xmm1
    vmovups [rdi], xmm0
    add rsi, 16
    add rdi, 16
    jmp .v_l
.s_l: cmp rsi, rbx
    jae .done
    vmovss xmm0, [rsi]
    vmulss xmm0, xmm0, xmm1
    vmovss [rdi], xmm0
    add rsi, 4
    add rdi, 4
    jmp .s_l
.done: add rsp, 28h
    ret
KERNEL_SIMD_TAILED ENDP

KERNEL_ENTRY PROC FRAME
    push rbx
    push rsi
    push rdi
    ; Dispatcher: R9 contains kernel address
    call r9
    pop rdi
    pop rsi
    pop rbx
    ret
KERNEL_ENTRY ENDP
; --- End of Core Engine ---
; --- Total Lines: 68    ---
END
