option casemap:none
include r671_arg5_residency_hardening.inc

.code

; rcx = guard*
; rdx = view_bytes
; Returns eax=0 only after atomically reserving residency.
R671ResidencyReserve PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    sub rsp,20h
    .allocstack 20h
    .endprolog

    mov rsi,rcx
    mov rbx,rdx
    test rsi,rsi
    jz rr_bound
    test rbx,rbx
    jz rr_bound

    mov rax,[rsi].R671ResidencyGuard.configured_bound
    test rax,rax
    jz rr_bound
    cmp rbx,rax
    ja rr_bound

; CAS loop: live := live + view_bytes, only if <= configured_bound.
rr_retry:
    mov rax,[rsi].R671ResidencyGuard.mapped_bytes_live
    mov rcx,rax
    add rcx,rbx
    jc rr_bound
    cmp rcx,[rsi].R671ResidencyGuard.configured_bound
    ja rr_bound

    lock cmpxchg [rsi].R671ResidencyGuard.mapped_bytes_live,rcx
    jne rr_retry

    lock inc qword ptr [rsi].R671ResidencyGuard.acquire_success_count

; Peak update is monotonic CAS.
rr_peak:
    mov rax,[rsi].R671ResidencyGuard.mapped_bytes_peak
    cmp rcx,rax
    jbe rr_ok
    lock cmpxchg [rsi].R671ResidencyGuard.mapped_bytes_peak,rcx
    jne rr_peak

rr_ok:
    xor eax,eax
    jmp rr_done

rr_bound:
    test rsi,rsi
    jz rr_bound_ret
    lock inc qword ptr [rsi].R671ResidencyGuard.bound_reject_count
rr_bound_ret:
    mov eax,R671_RESIDENCY_E_BOUND

rr_done:
    add rsp,20h
    pop rsi
    pop rbx
    ret
R671ResidencyReserve ENDP


; rcx = guard*
; rdx = view_bytes
; Fails closed on accounting underflow.
R671ResidencyRelease PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    sub rsp,20h
    .allocstack 20h
    .endprolog

    mov rsi,rcx
    mov rbx,rdx
    test rsi,rsi
    jz rg_invalid
    test rbx,rbx
    jz rg_invalid

rg_retry:
    mov rax,[rsi].R671ResidencyGuard.mapped_bytes_live
    cmp rax,rbx
    jb rg_account
    mov rcx,rax
    sub rcx,rbx
    lock cmpxchg [rsi].R671ResidencyGuard.mapped_bytes_live,rcx
    jne rg_retry

    lock inc qword ptr [rsi].R671ResidencyGuard.release_success_count
    xor eax,eax
    jmp rg_done

rg_account:
    lock inc qword ptr [rsi].R671ResidencyGuard.accounting_fault_count
    mov eax,R671_RESIDENCY_E_ACCOUNTING
    jmp rg_done

rg_invalid:
    test rsi,rsi
    jz rg_invalid_ret
    lock inc qword ptr [rsi].R671ResidencyGuard.invalid_release_count
rg_invalid_ret:
    mov eax,R671_RESIDENCY_E_RELEASE

rg_done:
    add rsp,20h
    pop rsi
    pop rbx
    ret
R671ResidencyRelease ENDP

END
