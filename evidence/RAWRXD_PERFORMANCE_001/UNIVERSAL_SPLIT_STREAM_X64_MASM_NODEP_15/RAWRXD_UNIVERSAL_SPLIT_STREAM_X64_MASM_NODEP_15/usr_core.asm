option casemap:none
include usr_universal.inc

.code

usr_ctx_init PROC
    test rcx,rcx
    jz bad
    mov qword ptr [rcx].USRContext.current_model_id,0
    mov qword ptr [rcx].USRContext.current_model_generation,0
    mov qword ptr [rcx].USRContext.current_op_ticket,0
    mov qword ptr [rcx].USRContext.current_owner,0
    mov qword ptr [rcx].USRContext.current_epoch,0
    mov qword ptr [rcx].USRContext.dynamic_ticket,0
    mov qword ptr [rcx].USRContext.dynamic_cookie,0
    mov [rcx].USRContext.host_budget,rdx
    mov qword ptr [rcx].USRContext.host_used,0
    mov [rcx].USRContext.gpu_budget,r8
    mov qword ptr [rcx].USRContext.gpu_used,0
    mov qword ptr [rcx].USRContext.stale_request_rejects,0
    mov qword ptr [rcx].USRContext.speculative_rejects,0
    mov qword ptr [rcx].USRContext.batch_validations,0
    mov qword ptr [rcx].USRContext.batch_rejects,0
    mov qword ptr [rcx].USRContext.model_switches,0
    xor eax,eax
    ret
bad:
    mov eax,USR_E_INVALID
    ret
usr_ctx_init ENDP

usr_begin_op PROC
    test rcx,rcx
    jz bad
    test rdx,rdx
    jz bad
    test r8,r8
    jz bad
    cmp qword ptr [rcx].USRContext.current_op_ticket,0
    jne busy
    mov [rcx].USRContext.current_op_ticket,rdx
    mov [rcx].USRContext.current_owner,r8
    inc qword ptr [rcx].USRContext.current_epoch
    mov qword ptr [rcx].USRContext.dynamic_ticket,0
    mov qword ptr [rcx].USRContext.dynamic_cookie,0
    xor eax,eax
    ret
busy:
    mov eax,USR_E_BUSY
    ret
bad:
    mov eax,USR_E_INVALID
    ret
usr_begin_op ENDP

usr_end_op PROC
    test rcx,rcx
    jz bad
    cmp [rcx].USRContext.current_op_ticket,rdx
    jne stale
    cmp [rcx].USRContext.current_owner,r8
    jne stale
    mov qword ptr [rcx].USRContext.current_op_ticket,0
    mov qword ptr [rcx].USRContext.current_owner,0
    mov qword ptr [rcx].USRContext.dynamic_ticket,0
    mov qword ptr [rcx].USRContext.dynamic_cookie,0
    xor eax,eax
    ret
stale:
    inc qword ptr [rcx].USRContext.stale_request_rejects
    mov eax,USR_E_STALE
    ret
bad:
    mov eax,USR_E_INVALID
    ret
usr_end_op ENDP

usr_switch_model PROC
    test rcx,rcx
    jz bad
    test rdx,rdx
    jz bad
    test r8,r8
    jz bad
    cmp qword ptr [rcx].USRContext.current_op_ticket,0
    jne busy
    mov [rcx].USRContext.current_model_id,rdx
    mov [rcx].USRContext.current_model_generation,r8
    inc qword ptr [rcx].USRContext.model_switches
    xor eax,eax
    ret
busy:
    mov eax,USR_E_BUSY
    ret
bad:
    mov eax,USR_E_INVALID
    ret
usr_switch_model ENDP

usr_validate_current PROC
    test rcx,rcx
    jz bad
    test r9,r9
    jz bad
    cmp [rcx].USRContext.current_op_ticket,rdx
    jne stale
    cmp [rcx].USRContext.current_owner,r8
    jne stale
    mov rax,[rcx].USRContext.current_model_id
    cmp rax,[r9].USRRegion.model_id
    jne stale
    mov rax,[rcx].USRContext.current_model_generation
    cmp rax,[r9].USRRegion.model_generation
    jne stale
    xor eax,eax
    ret
stale:
    inc qword ptr [rcx].USRContext.stale_request_rejects
    inc qword ptr [r9].USRRegion.stale_generation_faults
    mov eax,USR_E_STALE
    ret
bad:
    mov eax,USR_E_INVALID
    ret
usr_validate_current ENDP

usr_dynamic_observed PROC
    test rcx,rcx
    jz bad
    test rdx,rdx
    jz bad
    test r8,r8
    jz bad
    cmp [rcx].USRContext.current_op_ticket,rdx
    jne stale
    mov [rcx].USRContext.dynamic_ticket,rdx
    mov [rcx].USRContext.dynamic_cookie,r8
    xor eax,eax
    ret
stale:
    inc qword ptr [rcx].USRContext.stale_request_rejects
    mov eax,USR_E_STALE
    ret
bad:
    mov eax,USR_E_INVALID
    ret
usr_dynamic_observed ENDP

usr_validate_dynamic PROC
    test rcx,rcx
    jz bad
    cmp [rcx].USRContext.dynamic_ticket,rdx
    jne stale
    cmp [rcx].USRContext.dynamic_cookie,r8
    jne stale
    xor eax,eax
    ret
stale:
    inc qword ptr [rcx].USRContext.speculative_rejects
    mov eax,USR_E_STALE
    ret
bad:
    mov eax,USR_E_INVALID
    ret
usr_validate_dynamic ENDP

END
