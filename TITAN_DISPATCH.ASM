.CODE
PUBLIC TITAN_DISPATCH
TITAN_DISPATCH PROC FRAME       ; RCX:OpID, RDX:Src, R8:Dst, R9:Cnt
    sub rsp, 28h                ; ABI Shadow Space
    cmp rcx, 3                  ; Max OpID check
    ja .error
    jmp [dispatch_table + rcx*8]

.data
    dispatch_table dq Q4_K, Q5_K, SIMD_T, MATRIX
.code

Q4_K:                           ; 18-byte stride
    mov rax, r9
    lea rbx, [rax + rax*8]
    add rbx, rbx
    add rbx, rdx
    mov rsi, rdx
.loop_q4:
    cmp rsi, rbx
    jae .done
    vmovups xmm0, [rsi + 2]
    add rsi, 18
    jmp .loop_q4

Q5_K:                           ; 176-byte stride
    mov rax, r9
    lea rbx, [rax + rax*8]
    shl rbx, 4
    lea rbx, [rbx + rax*32]
    add rbx, rdx
    mov rsi, rdx
.loop_q5:
    cmp rsi, rbx
    jae .done
    vmovups xmm0, [rsi]
    add rsi, 176
    jmp .loop_q5

SIMD_T:                         ; Vector + Tail
    lea rbx, [rdx + r9*4]
    mov rsi, rdx
    mov rdi, r8
.loop_vec:
    cmp rsi, rbx
    jae .done
    vmovups xmm0, [rsi]
    vmovups [rdi], xmm0
    add rsi, 16
    add rdi, 16
    jmp .loop_vec

MATRIX:                         ; Self-terminating stride
    mov r10, rdx                ; RDX=RowStart
    mov r11, r8                 ; R8=Stride
    mov r12, r9                 ; R9=EndPtr
.loop_mat:
    cmp r10, r12
    jae .done
    add r10, r11
    jmp .loop_mat

.done:
    add rsp, 28h
    ret
.error:
    int 3                       ; Break on dispatch failure
    ret
TITAN_DISPATCH ENDP
END
