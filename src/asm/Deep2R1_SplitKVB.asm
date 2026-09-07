; Deep2R1_SplitKVB.asm — per-head [K_nope|V] deinterleave after fused GEMV
OPTION CASEMAP:NONE
INCLUDE Deep2R1TensorDecode.inc
PUBLIC Deep2R1_SplitKVBOutput

.code
; RCX=src RDX=dstK R8=dstV R9=Deep2R1KvbSplitDesc*
Deep2R1_SplitKVBOutput PROC PUBLIC
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    xor eax, eax
    test rcx, rcx
    jz R1S_Done
    test rdx, rdx
    jz R1S_Done
    test r8, r8
    jz R1S_Done
    test r9, r9
    jz R1S_Done
    mov rsi, rcx
    mov rdi, rdx
    mov r12, r8
    mov r13d, dword ptr [r9 + R1S_NUM_HEADS]
    mov r14d, dword ptr [r9 + R1S_K_DIM]
    mov r15d, dword ptr [r9 + R1S_V_DIM]
    test r13d, r13d
    jz R1S_Done
    test r14d, r14d
    jz R1S_Done
    test r15d, r15d
    jz R1S_Done
R1S_Head:
    xor ebx, ebx
R1S_CopyK:
    cmp ebx, r14d
    jae short R1S_KDone
    mov eax, dword ptr [rsi + rbx*4]
    mov dword ptr [rdi + rbx*4], eax
    inc ebx
    jmp short R1S_CopyK
R1S_KDone:
    xor ebx, ebx
    lea rcx, [rsi + r14*4]
R1S_CopyV:
    cmp ebx, r15d
    jae short R1S_VDone
    mov eax, dword ptr [rcx + rbx*4]
    mov dword ptr [r12 + rbx*4], eax
    inc ebx
    jmp short R1S_CopyV
R1S_VDone:
    mov eax, r14d
    add eax, r15d
    lea rsi, [rsi + rax*4]
    lea rdi, [rdi + r14*4]
    lea r12, [r12 + r15*4]
    dec r13d
    jnz R1S_Head
    mov eax, 1
R1S_Done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
Deep2R1_SplitKVBOutput ENDP
END
