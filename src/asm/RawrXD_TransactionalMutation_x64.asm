; RawrXD_TransactionalMutation_x64.asm — transactional mutation state machine (no CRT/heap)
option casemap:none
include RawrXD_TransactionalMutation_x64.inc
.code
PUBLIC RawrXD_TX_Init
PUBLIC RawrXD_TX_Begin
PUBLIC RawrXD_TX_Approve
PUBLIC RawrXD_TX_Prepare
PUBLIC RawrXD_TX_Commit
PUBLIC RawrXD_TX_BeginRollback
PUBLIC RawrXD_TX_FinishRollback
PUBLIC RawrXD_TX_Abort
PUBLIC RawrXD_TX_VerifyRecord

TX_ReadTsc PROC
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    ret
TX_ReadTsc ENDP

TX_Mix PROC
    xor     rax, rdx
    add     rax, r8
    mov     r9, rax
    shr     r9, 30
    xor     rax, r9
    mov     r9, 0BF58476D1CE4E5B9h
    imul    rax, r9
    mov     r9, rax
    shr     r9, 27
    xor     rax, r9
    mov     r9, 094D049BB133111EBh
    imul    rax, r9
    mov     r9, rax
    shr     r9, 31
    xor     rax, r9
    ret
TX_Mix ENDP

TX_SealRecord PROC
    push    rbx
    push    rsi
    push    rdi
    sub     rsp, 20h
    mov     rsi, rcx
    mov     rdi, rdx
    mov     rax, qword ptr [rsi+TXC_KEY0]
    xor     rax, qword ptr [rsi+TXC_KEY1]
    xor     rax, qword ptr [rdi+TXR_PREV_TAG]
    mov     rdx, qword ptr [rdi+00h]
    mov     r8, qword ptr [rsi+TXC_KEY0]
    call    TX_Mix
    mov     rdx, qword ptr [rdi+08h]
    mov     r8, qword ptr [rsi+TXC_KEY1]
    call    TX_Mix
    mov     rdx, qword ptr [rdi+10h]
    mov     r8, qword ptr [rsi+TXC_KEY0]
    call    TX_Mix
    mov     rdx, qword ptr [rdi+18h]
    mov     r8, qword ptr [rsi+TXC_KEY1]
    call    TX_Mix
    mov     rdx, qword ptr [rdi+20h]
    mov     r8, qword ptr [rsi+TXC_KEY0]
    call    TX_Mix
    mov     rdx, qword ptr [rdi+28h]
    mov     r8, qword ptr [rsi+TXC_KEY1]
    call    TX_Mix
    mov     rdx, qword ptr [rdi+30h]
    mov     r8, qword ptr [rsi+TXC_KEY0]
    call    TX_Mix
    mov     rdx, qword ptr [rdi+38h]
    mov     r8, qword ptr [rsi+TXC_KEY1]
    call    TX_Mix
    mov     rdx, qword ptr [rdi+40h]
    mov     r8, qword ptr [rsi+TXC_KEY0]
    call    TX_Mix
    mov     rdx, qword ptr [rdi+48h]
    mov     r8, qword ptr [rsi+TXC_KEY1]
    call    TX_Mix
    mov     rdx, qword ptr [rdi+50h]
    mov     r8, qword ptr [rsi+TXC_KEY0]
    call    TX_Mix
    mov     rdx, qword ptr [rdi+58h]
    mov     r8, qword ptr [rsi+TXC_KEY1]
    call    TX_Mix
    mov     rdx, qword ptr [rdi+60h]
    mov     r8, qword ptr [rsi+TXC_KEY0]
    call    TX_Mix
    mov     rdx, qword ptr [rdi+70h]
    mov     r8, qword ptr [rsi+TXC_KEY1]
    call    TX_Mix
    mov     rdx, 54584E5F41555448h
    mov     r8, 09E3779B97F4A7C15h
    call    TX_Mix
    test    rax, rax
    jnz     short txsr_ok
    mov     eax, 1
txsr_ok:
    add     rsp, 20h
    pop     rdi
    pop     rsi
    pop     rbx
    ret
TX_SealRecord ENDP

TX_Publish PROC
    push    rsi
    push    rdi
    sub     rsp, 28h
    mov     rsi, rcx
    mov     rdi, rdx
    mov     rax, qword ptr [rsi+TXC_CHAIN_TAG]
    mov     qword ptr [rdi+TXR_PREV_TAG], rax
    mov     rcx, rsi
    mov     rdx, rdi
    call    TX_SealRecord
    mov     qword ptr [rdi+TXR_TAG], rax
    mfence
    mov     qword ptr [rsi+TXC_CHAIN_TAG], rax
    add     rsp, 28h
    pop     rdi
    pop     rsi
    ret
TX_Publish ENDP

RawrXD_TX_Init PROC
    test    rcx, rcx
    jz      txi_fail
    test    rdx, rdx
    jz      txi_fail
    test    r8, r8
    jz      txi_fail
    mov     rax, qword ptr [rsp+40]
    mov     qword ptr [rcx+TXC_BASE], rdx
    mov     qword ptr [rcx+TXC_CAPACITY], r8
    xor     edx, edx
    mov     qword ptr [rcx+TXC_NEXT_ID], rdx
    mov     qword ptr [rcx+TXC_ACTIVE], rdx
    mov     qword ptr [rcx+TXC_COMMITTED], rdx
    mov     qword ptr [rcx+TXC_ROLLED_BACK], rdx
    mov     qword ptr [rcx+TXC_FAULTS], rdx
    mov     qword ptr [rcx+TXC_CHAIN_TAG], rdx
    mov     qword ptr [rcx+TXC_KEY0], r9
    mov     qword ptr [rcx+TXC_KEY1], rax
    mov     rax, TX_MAGIC
    mov     qword ptr [rcx+TXC_MAGIC], rax
    mov     rax, TX_VERSION
    mov     qword ptr [rcx+TXC_VERSION], rax
    mov     eax, 1
    ret
txi_fail:
    xor     eax, eax
    ret
RawrXD_TX_Init ENDP

RawrXD_TX_Begin PROC
    push    rbx
    push    rsi
    push    rdi
    push    r12
    sub     rsp, 28h
    mov     rsi, rcx
    mov     r12d, edx
    mov     rbx, r8
    mov     rdi, r9
    test    rsi, rsi
    jz      txb_fail
    mov     rax, qword ptr [rsi+TXC_MAGIC]
    mov     rcx, TX_MAGIC
    cmp     rax, rcx
    jne     txb_fail
    mov     rcx, qword ptr [rsi+TXC_CAPACITY]
    test    rcx, rcx
    jz      txb_fail
    mov     rax, qword ptr [rsi+TXC_NEXT_ID]
    inc     rax
    mov     qword ptr [rsi+TXC_NEXT_ID], rax
    mov     r8, rax
    dec     rax
    xor     edx, edx
    div     rcx
    shl     rdx, 7
    mov     rax, qword ptr [rsi+TXC_BASE]
    add     rax, rdx
    mov     rcx, rax
    mov     qword ptr [rcx+TXR_ID], r8
    mov     dword ptr [rcx+TXR_STATE], TX_STATE_BEGUN
    mov     dword ptr [rcx+TXR_KIND], r12d
    call    TX_ReadTsc
    mov     qword ptr [rcx+TXR_BEGIN_TSC], rax
    xor     eax, eax
    mov     qword ptr [rcx+TXR_END_TSC], rax
    mov     qword ptr [rcx+TXR_APPROVAL_SEQ], rax
    mov     qword ptr [rcx+TXR_AUTHORITY_SEQ], rax
    mov     qword ptr [rcx+TXR_TARGET_HASH], rbx
    mov     qword ptr [rcx+TXR_PREIMAGE_HASH], rax
    mov     qword ptr [rcx+TXR_POSTIMAGE_HASH], rax
    mov     qword ptr [rcx+TXR_BACKUP_HASH], rax
    mov     qword ptr [rcx+TXR_BYTES_EXPECTED], rdi
    mov     qword ptr [rcx+TXR_BYTES_WRITTEN], rax
    mov     qword ptr [rcx+TXR_PREV_TAG], rax
    mov     qword ptr [rcx+TXR_TAG], rax
    mov     qword ptr [rcx+TXR_ERROR], rax
    mov     qword ptr [rcx+TXR_RESERVED], rax
    mov     rax, qword ptr [rsi+TXC_ACTIVE]
    inc     rax
    mov     qword ptr [rsi+TXC_ACTIVE], rax
    mov     rdi, rcx
    mov     rcx, rsi
    mov     rdx, rdi
    call    TX_Publish
    mov     rax, rdi
    jmp     short txb_exit
txb_fail:
    xor     eax, eax
txb_exit:
    add     rsp, 28h
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
RawrXD_TX_Begin ENDP

RawrXD_TX_Approve PROC
    push    rsi
    push    rdi
    sub     rsp, 28h
    mov     rsi, rcx
    mov     rdi, rdx
    test    rsi, rsi
    jz      txa_fail
    test    rdi, rdi
    jz      txa_fail
    cmp     dword ptr [rdi+TXR_STATE], TX_STATE_BEGUN
    jne     txa_fail
    test    r8, r8
    jz      txa_fail
    mov     qword ptr [rdi+TXR_APPROVAL_SEQ], r8
    mov     qword ptr [rdi+TXR_AUTHORITY_SEQ], r9
    mov     dword ptr [rdi+TXR_STATE], TX_STATE_APPROVED
    mov     rcx, rsi
    mov     rdx, rdi
    call    TX_Publish
    mov     eax, 1
    jmp     short txa_exit
txa_fail:
    xor     eax, eax
txa_exit:
    add     rsp, 28h
    pop     rdi
    pop     rsi
    ret
RawrXD_TX_Approve ENDP

RawrXD_TX_Prepare PROC
    push    rsi
    push    rdi
    sub     rsp, 28h
    mov     rsi, rcx
    mov     rdi, rdx
    test    rsi, rsi
    jz      txp_fail
    test    rdi, rdi
    jz      txp_fail
    cmp     dword ptr [rdi+TXR_STATE], TX_STATE_APPROVED
    jne     txp_fail
    cmp     qword ptr [rdi+TXR_APPROVAL_SEQ], 0
    je      txp_fail
    mov     qword ptr [rdi+TXR_PREIMAGE_HASH], r8
    mov     qword ptr [rdi+TXR_BACKUP_HASH], r9
    mov     dword ptr [rdi+TXR_STATE], TX_STATE_MUTATING
    mov     rcx, rsi
    mov     rdx, rdi
    call    TX_Publish
    mov     eax, 1
    jmp     short txp_exit
txp_fail:
    xor     eax, eax
txp_exit:
    add     rsp, 28h
    pop     rdi
    pop     rsi
    ret
RawrXD_TX_Prepare ENDP

RawrXD_TX_Commit PROC
    push    rsi
    push    rdi
    sub     rsp, 28h
    mov     rsi, rcx
    mov     rdi, rdx
    test    rsi, rsi
    jz      txc_fail
    test    rdi, rdi
    jz      txc_fail
    cmp     dword ptr [rdi+TXR_STATE], TX_STATE_MUTATING
    jne     txc_fail
    mov     qword ptr [rdi+TXR_POSTIMAGE_HASH], r8
    mov     qword ptr [rdi+TXR_BYTES_WRITTEN], r9
    call    TX_ReadTsc
    mov     qword ptr [rdi+TXR_END_TSC], rax
    mov     dword ptr [rdi+TXR_STATE], TX_STATE_COMMITTED
    mov     rcx, rsi
    mov     rdx, rdi
    call    TX_Publish
    mov     rax, qword ptr [rsi+TXC_ACTIVE]
    test    rax, rax
    jz      short txc_no_active
    dec     rax
    mov     qword ptr [rsi+TXC_ACTIVE], rax
txc_no_active:
    mov     rax, qword ptr [rsi+TXC_COMMITTED]
    inc     rax
    mov     qword ptr [rsi+TXC_COMMITTED], rax
    mov     eax, 1
    jmp     short txc_exit
txc_fail:
    xor     eax, eax
txc_exit:
    add     rsp, 28h
    pop     rdi
    pop     rsi
    ret
RawrXD_TX_Commit ENDP

RawrXD_TX_BeginRollback PROC
    push    rsi
    push    rdi
    sub     rsp, 28h
    mov     rsi, rcx
    mov     rdi, rdx
    test    rsi, rsi
    jz      txbr_fail
    test    rdi, rdi
    jz      txbr_fail
    mov     eax, dword ptr [rdi+TXR_STATE]
    cmp     eax, TX_STATE_BEGUN
    je      txbr_allowed
    cmp     eax, TX_STATE_APPROVED
    je      txbr_allowed
    cmp     eax, TX_STATE_MUTATING
    jne     txbr_fail
txbr_allowed:
    mov     qword ptr [rdi+TXR_ERROR], r8
    mov     dword ptr [rdi+TXR_STATE], TX_STATE_ROLLBACK
    mov     rcx, rsi
    mov     rdx, rdi
    call    TX_Publish
    mov     eax, 1
    jmp     short txbr_exit
txbr_fail:
    xor     eax, eax
txbr_exit:
    add     rsp, 28h
    pop     rdi
    pop     rsi
    ret
RawrXD_TX_BeginRollback ENDP

RawrXD_TX_FinishRollback PROC
    push    rsi
    push    rdi
    sub     rsp, 28h
    mov     rsi, rcx
    mov     rdi, rdx
    test    rsi, rsi
    jz      txfr_fail
    test    rdi, rdi
    jz      txfr_fail
    cmp     dword ptr [rdi+TXR_STATE], TX_STATE_ROLLBACK
    jne     txfr_fail
    mov     rax, qword ptr [rdi+TXR_PREIMAGE_HASH]
    test    rax, rax
    jz      short txfr_accept
    cmp     rax, r8
    jne     txfr_fault
txfr_accept:
    mov     qword ptr [rdi+TXR_POSTIMAGE_HASH], r8
    call    TX_ReadTsc
    mov     qword ptr [rdi+TXR_END_TSC], rax
    mov     dword ptr [rdi+TXR_STATE], TX_STATE_ROLLED_BACK
    mov     rcx, rsi
    mov     rdx, rdi
    call    TX_Publish
    mov     rax, qword ptr [rsi+TXC_ACTIVE]
    test    rax, rax
    jz      short txfr_count
    dec     rax
    mov     qword ptr [rsi+TXC_ACTIVE], rax
txfr_count:
    mov     rax, qword ptr [rsi+TXC_ROLLED_BACK]
    inc     rax
    mov     qword ptr [rsi+TXC_ROLLED_BACK], rax
    mov     eax, 1
    jmp     short txfr_exit
txfr_fault:
    mov     dword ptr [rdi+TXR_STATE], TX_STATE_FAULT
    mov     rax, qword ptr [rsi+TXC_FAULTS]
    inc     rax
    mov     qword ptr [rsi+TXC_FAULTS], rax
    mov     rcx, rsi
    mov     rdx, rdi
    call    TX_Publish
    xor     eax, eax
    jmp     short txfr_exit
txfr_fail:
    xor     eax, eax
txfr_exit:
    add     rsp, 28h
    pop     rdi
    pop     rsi
    ret
RawrXD_TX_FinishRollback ENDP

RawrXD_TX_Abort PROC
    push    rsi
    push    rdi
    sub     rsp, 28h
    mov     rsi, rcx
    mov     rdi, rdx
    test    rsi, rsi
    jz      txab_fail
    test    rdi, rdi
    jz      txab_fail
    mov     eax, dword ptr [rdi+TXR_STATE]
    cmp     eax, TX_STATE_BEGUN
    je      txab_allowed
    cmp     eax, TX_STATE_APPROVED
    jne     txab_fail
txab_allowed:
    mov     qword ptr [rdi+TXR_ERROR], r8
    call    TX_ReadTsc
    mov     qword ptr [rdi+TXR_END_TSC], rax
    mov     dword ptr [rdi+TXR_STATE], TX_STATE_ABORTED
    mov     rcx, rsi
    mov     rdx, rdi
    call    TX_Publish
    mov     rax, qword ptr [rsi+TXC_ACTIVE]
    test    rax, rax
    jz      short txab_success
    dec     rax
    mov     qword ptr [rsi+TXC_ACTIVE], rax
txab_success:
    mov     eax, 1
    jmp     short txab_exit
txab_fail:
    xor     eax, eax
txab_exit:
    add     rsp, 28h
    pop     rdi
    pop     rsi
    ret
RawrXD_TX_Abort ENDP

RawrXD_TX_VerifyRecord PROC
    push    rsi
    push    rdi
    sub     rsp, 28h
    mov     rsi, rcx
    mov     rdi, rdx
    test    rsi, rsi
    jz      txv_fail
    test    rdi, rdi
    jz      txv_fail
    mov     rcx, rsi
    mov     rdx, rdi
    call    TX_SealRecord
    cmp     rax, qword ptr [rdi+TXR_TAG]
    jne     txv_fail
    jmp     short txv_exit
txv_fail:
    xor     eax, eax
txv_exit:
    add     rsp, 28h
    pop     rdi
    pop     rsi
    ret
RawrXD_TX_VerifyRecord ENDP

END
