option casemap:none
include usr_universal.inc

.code

usr_batch_validate PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    push r12
    .pushreg r12
    sub rsp,28h
    .allocstack 28h
    .endprolog

    mov rbx,rcx
    mov rsi,rdx
    mov rdi,r8
    mov r10,r9
    mov r11,[rsp+70h]
    test rbx,rbx
    jz bad
    test rsi,rsi
    jz bad
    test rdi,rdi
    jz bad
    xor r12d,r12d
loop_regions:
    cmp r12,rdi
    jae pass
    mov r9,[rsi+r12*8]
    test r9,r9
    jz reject
    mov rcx,rbx
    mov rdx,r10
    mov r8,r11
    call usr_validate_current
    test eax,eax
    jnz reject
    inc r12
    jmp loop_regions
pass:
    inc qword ptr [rbx].USRContext.batch_validations
    xor eax,eax
    jmp done
reject:
    inc qword ptr [rbx].USRContext.batch_rejects
    mov eax,USR_E_STALE
    jmp done
bad:
    mov eax,USR_E_INVALID
done:
    add rsp,28h
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
usr_batch_validate ENDP

usr_receipt_region PROC
    test rcx,rcx
    jz bad
    test rdx,rdx
    jz bad
    mov qword ptr [rdx].USRReceipt.pass,0
    mov rax,[rcx].USRRegion.mg_bytes
    mov [rdx].USRReceipt.mg_bytes,rax
    mov rax,[rcx].USRRegion.physical_bytes
    mov [rdx].USRReceipt.physical_bytes,rax
    mov rax,[rcx].USRRegion.physical_reads
    mov [rdx].USRReceipt.physical_reads,rax
    mov rax,[rcx].USRRegion.mg_loads
    mov [rdx].USRReceipt.mg_loads,rax
    mov rax,[rcx].USRRegion.duplicate_first_touch
    mov [rdx].USRReceipt.duplicate_first_touch,rax
    mov rax,[rcx].USRRegion.stale_generation_faults
    mov [rdx].USRReceipt.stale_generation_faults,rax

    mov rax,[rdx].USRReceipt.mg_bytes
    cmp rax,[rdx].USRReceipt.physical_bytes
    jne done
    cmp qword ptr [rdx].USRReceipt.duplicate_first_touch,0
    jne done
    cmp qword ptr [rdx].USRReceipt.stale_generation_faults,0
    jne done
    mov qword ptr [rdx].USRReceipt.pass,1
done:
    xor eax,eax
    ret
bad:
    mov eax,USR_E_INVALID
    ret
usr_receipt_region ENDP

END
