; deep2_auth_grant.asm — AttemptGrantAuthority / Revoke / Query
OPTION CASEMAP:NONE
include deep2_auth_abi.inc

PUBLIC Deep2AuthInit
PUBLIC Deep2AttemptGrantAuthority
PUBLIC Deep2AuthRevoke
PUBLIC Deep2AuthQuery

.code

; RCX=state, EDX=model_gen, R8D=decode_gen, R9D=ticket
Deep2AuthInit PROC
    test rcx, rcx
    jz dai_fail
    xor eax, eax
    mov qword ptr [rcx + D2_AS_GRANTED_MASK], rax
    mov dword ptr [rcx + D2_AS_MODEL_GEN], edx
    mov dword ptr [rcx + D2_AS_DECODE_GEN], r8d
    mov dword ptr [rcx + D2_AS_TICKET], r9d
    mov dword ptr [rcx + D2_AS_LAST_STATUS], D2_AUTH_UNPROVEN
    mov eax, 1
    ret
dai_fail:
    xor eax, eax
    ret
Deep2AuthInit ENDP

; RCX=state, RDX=witness*
; EAX=1 granted, 0 no grant. Sets LAST_STATUS.
Deep2AttemptGrantAuthority PROC
    test rcx, rcx
    jz dag_fail
    test rdx, rdx
    jz dag_fail

    cmp dword ptr [rdx + D2_AW_EXECUTED], 1
    jne dag_reject
    cmp dword ptr [rdx + D2_AW_COMPLETED], 1
    jne dag_reject
    cmp dword ptr [rdx + D2_AW_ERROR], 0
    jne dag_reject
    cmp dword ptr [rdx + D2_AW_SYNTHETIC], 0
    jne dag_reject
    cmp dword ptr [rdx + D2_AW_FALLBACK], 0
    jne dag_reject

    mov eax, dword ptr [rdx + D2_AW_MODEL_GEN]
    cmp eax, dword ptr [rdx + D2_AW_CUR_MODEL_GEN]
    jne dag_reject
    cmp eax, dword ptr [rcx + D2_AS_MODEL_GEN]
    jne dag_reject

    mov eax, dword ptr [rdx + D2_AW_DECODE_GEN]
    cmp eax, dword ptr [rdx + D2_AW_CUR_DECODE_GEN]
    jne dag_reject
    cmp eax, dword ptr [rcx + D2_AS_DECODE_GEN]
    jne dag_reject

    mov eax, dword ptr [rdx + D2_AW_TICKET]
    cmp eax, dword ptr [rdx + D2_AW_CUR_TICKET]
    jne dag_reject
    cmp eax, dword ptr [rcx + D2_AS_TICKET]
    jne dag_reject

    mov eax, dword ptr [rdx + D2_AW_OBS_COUNTER]
    cmp eax, dword ptr [rdx + D2_AW_EXP_COUNTER]
    jne dag_reject
    test eax, eax
    jz dag_reject

    mov eax, dword ptr [rdx + D2_AW_FLAGS]
    mov r8d, dword ptr [rdx + D2_AW_REQ_FLAGS]
    test r8d, r8d
    jz dag_reject
    mov r9d, eax
    and r9d, r8d
    cmp r9d, r8d
    jne dag_reject

    mov rax, qword ptr [rdx + D2_AW_BIT]
    test rax, rax
    jz dag_reject
    or qword ptr [rcx + D2_AS_GRANTED_MASK], rax
    mov dword ptr [rcx + D2_AS_LAST_STATUS], D2_AUTH_GRANTED
    mov eax, 1
    ret

dag_reject:
    mov dword ptr [rcx + D2_AS_LAST_STATUS], D2_AUTH_UNPROVEN
dag_fail:
    xor eax, eax
    ret
Deep2AttemptGrantAuthority ENDP

; RCX=state, RDX=bitmask to clear
Deep2AuthRevoke PROC
    test rcx, rcx
    jz dar_fail
    not rdx
    and qword ptr [rcx + D2_AS_GRANTED_MASK], rdx
    mov dword ptr [rcx + D2_AS_LAST_STATUS], D2_AUTH_REVOKED
    mov eax, 1
    ret
dar_fail:
    xor eax, eax
    ret
Deep2AuthRevoke ENDP

; RCX=state, RDX=bit → EAX=1 if granted
Deep2AuthQuery PROC
    test rcx, rcx
    jz daq_no
    mov rax, qword ptr [rcx + D2_AS_GRANTED_MASK]
    and rax, rdx
    setnz al
    movzx eax, al
    ret
daq_no:
    xor eax, eax
    ret
Deep2AuthQuery ENDP

END
