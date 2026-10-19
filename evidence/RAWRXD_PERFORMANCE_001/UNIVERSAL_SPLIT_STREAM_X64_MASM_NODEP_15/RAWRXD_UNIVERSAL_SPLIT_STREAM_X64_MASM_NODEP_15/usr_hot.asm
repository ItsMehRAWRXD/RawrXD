option casemap:none
include usr_universal.inc

.code

usr_hot_commit PROC FRAME
    sub rsp,28h
    .allocstack 28h
    .endprolog
    test rcx,rcx
    jz bad
    cmp dword ptr [rcx].USRRegion.state,USR_HOT
    je duplicate
    cmp dword ptr [rcx].USRRegion.state,USR_WARM
    jne state_bad
    cmp [rcx].USRRegion.residency_generation,rdx
    jne stale
    cmp qword ptr [rcx].USRRegion.pin_count,0
    je busy

    mov r10,[rsp+50h]
    mov r11,[rsp+58h]
    test r10,r10
    jz bad
    mov rax,[rcx].USRRegion.byte_length
    cmp r11,rax
    jb range_bad

    mov [rcx].USRRegion.device_id,r8
    mov [rcx].USRRegion.device_alloc_generation,r9
    mov [rcx].USRRegion.device_handle,r10
    add [rcx].USRRegion.gpu_copy_bytes,rax
    inc qword ptr [rcx].USRRegion.gpu_uploads
    mov dword ptr [rcx].USRRegion.state,USR_HOT
    xor eax,eax
    jmp done
duplicate:
    inc qword ptr [rcx].USRRegion.duplicate_gpu_uploads
    mov eax,USR_E_DUP
    jmp done
stale:
    inc qword ptr [rcx].USRRegion.stale_generation_faults
    mov eax,USR_E_STALE
    jmp done
busy:
    mov eax,USR_E_BUSY
    jmp done
range_bad:
    mov eax,USR_E_RANGE
    jmp done
state_bad:
    mov eax,USR_E_STATE
    jmp done
bad:
    mov eax,USR_E_INVALID
done:
    add rsp,28h
    ret
usr_hot_commit ENDP

usr_hot_reset PROC
    test rcx,rcx
    jz bad
    cmp [rcx].USRRegion.device_alloc_generation,rdx
    jne stale
    cmp dword ptr [rcx].USRRegion.state,USR_HOT
    jne state_bad
    mov qword ptr [rcx].USRRegion.device_handle,0
    mov qword ptr [rcx].USRRegion.device_id,0
    inc qword ptr [rcx].USRRegion.device_alloc_generation
    cmp qword ptr [rcx].USRRegion.host_ptr,0
    je cold
    mov dword ptr [rcx].USRRegion.state,USR_WARM
    xor eax,eax
    ret
cold:
    mov dword ptr [rcx].USRRegion.state,USR_COLD
    xor eax,eax
    ret
stale:
    inc qword ptr [rcx].USRRegion.stale_generation_faults
    mov eax,USR_E_STALE
    ret
state_bad:
    mov eax,USR_E_STATE
    ret
bad:
    mov eax,USR_E_INVALID
    ret
usr_hot_reset ENDP

usr_hot_identity PROC
    test rcx,rcx
    jz bad
    test rdx,rdx
    jz bad
    cmp dword ptr [rcx].USRRegion.state,USR_HOT
    jne state_bad
    mov rax,[rcx].USRRegion.model_id
    mov [rdx].USRHotIdentity.model_id,rax
    mov rax,[rcx].USRRegion.model_generation
    mov [rdx].USRHotIdentity.model_generation,rax
    mov rax,[rcx].USRRegion.region_id
    mov [rdx].USRHotIdentity.region_id,rax
    mov rax,[rcx].USRRegion.residency_generation
    mov [rdx].USRHotIdentity.residency_generation,rax
    mov rax,[rcx].USRRegion.device_id
    mov [rdx].USRHotIdentity.device_id,rax
    mov rax,[rcx].USRRegion.device_alloc_generation
    mov [rdx].USRHotIdentity.allocation_generation,rax
    mov rax,[rcx].USRRegion.device_handle
    mov [rdx].USRHotIdentity.device_handle,rax
    mov rax,[rcx].USRRegion.byte_length
    mov [rdx].USRHotIdentity.byte_length,rax
    xor eax,eax
    ret
state_bad:
    mov eax,USR_E_STATE
    ret
bad:
    mov eax,USR_E_INVALID
    ret
usr_hot_identity ENDP

END
