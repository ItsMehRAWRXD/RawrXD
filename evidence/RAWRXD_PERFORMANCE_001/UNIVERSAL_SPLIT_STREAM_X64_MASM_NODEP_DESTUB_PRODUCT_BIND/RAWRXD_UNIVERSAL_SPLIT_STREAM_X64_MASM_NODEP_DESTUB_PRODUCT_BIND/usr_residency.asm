option casemap:none
include usr_universal.inc

.code

usr_region_prepare PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    sub rsp,28h
    .allocstack 28h
    .endprolog
    mov rbx,rcx
    mov rsi,rdx
    test rbx,rbx
    jz bad
    test rsi,rsi
    jz bad

    mov rcx,rbx
    mov rdx,r8
    mov r8,r9
    mov r9,rsi
    call usr_validate_current
    test eax,eax
    jnz done

    mov eax,[rsi].USRRegion.state
    cmp eax,USR_HOT
    je hot
    cmp eax,USR_WARM
    je warm
    cmp eax,USR_MG_IN_PROGRESS
    je join
    cmp eax,USR_COLD
    jne state_bad

    mov eax,USR_COLD
    mov ecx,USR_MG_IN_PROGRESS
    lock cmpxchg dword ptr [rsi].USRRegion.state,ecx
    jne lost
    inc qword ptr [rsi].USRRegion.mg_claim_winners
    mov eax,USR_PREP_CLAIM_WIN
    jmp done

lost:
    cmp eax,USR_MG_IN_PROGRESS
    je join
    cmp eax,USR_WARM
    je warm
    cmp eax,USR_HOT
    je hot
    inc qword ptr [rsi].USRRegion.duplicate_first_touch
    mov eax,USR_E_DUP
    jmp done
join:
    inc qword ptr [rsi].USRRegion.waiters
    mov eax,USR_PREP_JOIN
    jmp done
warm:
    inc qword ptr [rsi].USRRegion.warm_hits
    mov eax,USR_PREP_WARM_HIT
    jmp done
hot:
    inc qword ptr [rsi].USRRegion.hot_hits
    mov eax,USR_PREP_HOT_HIT
    jmp done
state_bad:
    mov eax,USR_E_STATE
    jmp done
bad:
    mov eax,USR_E_INVALID
done:
    add rsp,28h
    pop rsi
    pop rbx
    ret
usr_region_prepare ENDP

usr_commit_warm PROC
    test rcx,rcx
    jz bad
    test rdx,rdx
    jz bad
    cmp dword ptr [rcx].USRRegion.state,USR_MG_IN_PROGRESS
    jne state_bad
    mov rax,[rcx].USRRegion.byte_length
    cmp r8,rax
    jb range_bad
    cmp r9,rax
    jne range_bad
    mov [rcx].USRRegion.host_ptr,rdx
    mov [rcx].USRRegion.host_bytes,r8
    inc qword ptr [rcx].USRRegion.residency_generation
    inc qword ptr [rcx].USRRegion.physical_reads
    add [rcx].USRRegion.physical_bytes,r9
    inc qword ptr [rcx].USRRegion.mg_loads
    add [rcx].USRRegion.mg_bytes,r9
    mov dword ptr [rcx].USRRegion.state,USR_WARM
    xor eax,eax
    ret
state_bad:
    mov eax,USR_E_STATE
    ret
range_bad:
    mov eax,USR_E_RANGE
    ret
bad:
    mov eax,USR_E_INVALID
    ret
usr_commit_warm ENDP

usr_fail_mg PROC
    test rcx,rcx
    jz bad
    cmp dword ptr [rcx].USRRegion.state,USR_MG_IN_PROGRESS
    jne state_bad
    mov dword ptr [rcx].USRRegion.state,USR_COLD
    xor eax,eax
    ret
state_bad:
    mov eax,USR_E_STATE
    ret
bad:
    mov eax,USR_E_INVALID
    ret
usr_fail_mg ENDP

usr_join_wait PROC
    test rcx,rcx
    jz bad
spin_wait:
    mov eax,[rcx].USRRegion.state
    cmp eax,USR_MG_IN_PROGRESS
    jne completed
    pause
    jmp spin_wait
completed:
    cmp eax,USR_WARM
    je joined
    cmp eax,USR_HOT
    je joined
    mov eax,USR_E_STATE
    ret
joined:
    mov rax,[rcx].USRRegion.residency_generation
    cmp rax,rdx
    jbe stale
    inc qword ptr [rcx].USRRegion.joins
    xor eax,eax
    ret
stale:
    inc qword ptr [rcx].USRRegion.stale_generation_faults
    mov eax,USR_E_STALE
    ret
bad:
    mov eax,USR_E_INVALID
    ret
usr_join_wait ENDP

usr_pin PROC
    test rcx,rcx
    jz bad
    lock inc qword ptr [rcx].USRRegion.pin_count
    xor eax,eax
    ret
bad:
    mov eax,USR_E_INVALID
    ret
usr_pin ENDP

usr_unpin PROC
    test rcx,rcx
    jz bad
retry:
    mov rax,[rcx].USRRegion.pin_count
    test rax,rax
    jz state_bad
    lea rdx,[rax-1]
    lock cmpxchg qword ptr [rcx].USRRegion.pin_count,rdx
    jne retry
    xor eax,eax
    ret
state_bad:
    mov eax,USR_E_STATE
    ret
bad:
    mov eax,USR_E_INVALID
    ret
usr_unpin ENDP

usr_evict PROC
    test rcx,rcx
    jz bad
    cmp [rcx].USRRegion.residency_generation,rdx
    jne stale
    cmp qword ptr [rcx].USRRegion.pin_count,0
    jne busy
    mov eax,[rcx].USRRegion.state
    cmp eax,USR_WARM
    je go
    cmp eax,USR_HOT
    jne state_bad
go:
    mov qword ptr [rcx].USRRegion.host_ptr,0
    mov qword ptr [rcx].USRRegion.host_bytes,0
    mov qword ptr [rcx].USRRegion.device_handle,0
    mov qword ptr [rcx].USRRegion.device_id,0
    inc qword ptr [rcx].USRRegion.device_alloc_generation
    inc qword ptr [rcx].USRRegion.residency_generation
    inc qword ptr [rcx].USRRegion.evictions
    mov dword ptr [rcx].USRRegion.state,USR_COLD
    xor eax,eax
    ret
stale:
    inc qword ptr [rcx].USRRegion.stale_generation_faults
    mov eax,USR_E_STALE
    ret
busy:
    mov eax,USR_E_BUSY
    ret
state_bad:
    mov eax,USR_E_STATE
    ret
bad:
    mov eax,USR_E_INVALID
    ret
usr_evict ENDP

END
