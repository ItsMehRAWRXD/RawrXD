option casemap:none
include usr_universal.inc

ExitProcess PROTO :DWORD

.data
ctx USRContext <>
region USRRegion <>
receipt USRReceipt <>
buf BYTE 4096 DUP(5)

.code
main PROC FRAME
    sub rsp,28h
    .allocstack 28h
    .endprolog

    lea rcx,ctx
    mov rdx,8192
    mov r8,4096
    call usr_ctx_init
    test eax,eax
    jnz bad

    lea rcx,ctx
    mov rdx,1
    mov r8,1
    call usr_switch_model
    test eax,eax
    jnz bad

    mov region.model_id,1
    mov region.model_generation,1
    mov region.region_id,77
    mov region.provider_id,1
    mov region.file_offset,0
    mov region.byte_length,4096
    mov region.state,USR_COLD

    lea rcx,ctx
    mov rdx,100
    mov r8,200
    call usr_begin_op
    test eax,eax
    jnz bad

    lea rcx,ctx
    lea rdx,region
    mov r8,100
    mov r9,200
    call usr_region_prepare
    cmp eax,USR_PREP_CLAIM_WIN
    jne bad

    lea rcx,region
    lea rdx,buf
    mov r8,4096
    mov r9,4096
    call usr_commit_warm
    test eax,eax
    jnz bad

    lea rcx,ctx
    lea rdx,region
    mov r8,100
    mov r9,200
    call usr_region_prepare
    cmp eax,USR_PREP_WARM_HIT
    jne bad

    lea rcx,region
    lea rdx,receipt
    call usr_receipt_region
    test eax,eax
    jnz bad
    cmp receipt.pass,1
    jne bad

    lea rcx,ctx
    mov rdx,100
    mov r8,200
    call usr_end_op
    test eax,eax
    jnz bad

    xor ecx,ecx
    call ExitProcess
bad:
    mov ecx,1
    call ExitProcess
main ENDP
END
