option casemap:none
include usr_universal.inc

.code

usr_alias_acquire PROC FRAME
    sub rsp,28h
    .allocstack 28h
    .endprolog
    test rcx,rcx
    jz bad
    test r8,r8
    jz bad
    test r9,r9
    jz bad
    mov r10,[rsp+50h]
    test r10,r10
    jz bad

    mov eax,[rcx].USRRegion.state
    cmp eax,USR_WARM
    je resident
    cmp eax,USR_HOT
    jne state_bad
resident:
    mov r11,[rcx].USRRegion.file_offset
    mov rax,r11
    add rax,[rcx].USRRegion.byte_length
    jc range_bad                  ; rax = parent_end

    add r8,rdx
    jc range_bad                  ; r8 = child_end

    ; no overlap
    cmp r8,r11
    jbe range_bad
    cmp rdx,rax
    jae range_bad

    ; overlap exists; require full containment
    cmp rdx,r11
    jb partial
    cmp r8,rax
    ja partial

    lock inc qword ptr [rcx].USRRegion.pin_count
    mov rax,rdx
    sub rax,r11
    add rax,[rcx].USRRegion.host_ptr
    mov [r9],rax
    mov rax,[rcx].USRRegion.residency_generation
    mov [r10],rax
    inc qword ptr [rcx].USRRegion.alias_hits
    xor eax,eax
    jmp done
partial:
    inc qword ptr [rcx].USRRegion.alias_partial_rejects
    mov eax,USR_E_PARTIAL_ALIAS
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
usr_alias_acquire ENDP

usr_alias_release PROC
    jmp usr_unpin
usr_alias_release ENDP

budget_reserve PROC
retry:
    mov rax,[rcx]
    mov r9,rax
    add r9,r8
    jc fail
    cmp r9,rdx
    ja fail
    lock cmpxchg qword ptr [rcx],r9
    jne retry
    xor eax,eax
    ret
fail:
    mov eax,USR_E_BUDGET
    ret
budget_reserve ENDP

budget_release PROC
retry:
    mov rax,[rcx]
    cmp rax,rdx
    jb fail
    mov r8,rax
    sub r8,rdx
    lock cmpxchg qword ptr [rcx],r8
    jne retry
    xor eax,eax
    ret
fail:
    mov eax,USR_E_STATE
    ret
budget_release ENDP

usr_host_reserve PROC
    test rcx,rcx
    jz bad
    mov r8,rdx
    mov rdx,[rcx].USRContext.host_budget
    lea rcx,[rcx].USRContext.host_used
    jmp budget_reserve
bad:
    mov eax,USR_E_INVALID
    ret
usr_host_reserve ENDP

usr_host_release PROC
    test rcx,rcx
    jz bad
    lea rcx,[rcx].USRContext.host_used
    jmp budget_release
bad:
    mov eax,USR_E_INVALID
    ret
usr_host_release ENDP

usr_gpu_reserve PROC
    test rcx,rcx
    jz bad
    mov r8,rdx
    mov rdx,[rcx].USRContext.gpu_budget
    lea rcx,[rcx].USRContext.gpu_used
    jmp budget_reserve
bad:
    mov eax,USR_E_INVALID
    ret
usr_gpu_reserve ENDP

usr_gpu_release PROC
    test rcx,rcx
    jz bad
    lea rcx,[rcx].USRContext.gpu_used
    jmp budget_release
bad:
    mov eax,USR_E_INVALID
    ret
usr_gpu_release ENDP

END
