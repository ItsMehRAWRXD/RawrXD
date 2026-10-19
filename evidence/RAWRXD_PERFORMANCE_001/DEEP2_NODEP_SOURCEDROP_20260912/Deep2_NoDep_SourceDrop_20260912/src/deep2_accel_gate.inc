; Macro used by acceleration ABI wrappers. The wrapper itself never claims math happened:
; it invokes the bound product function and writes its observation bit only on success.
D2_DEFINE_GATE MACRO procname:req, obsbit:req
PUBLIC procname
procname PROC FRAME
    push rbx
    .pushreg rbx
    sub rsp, 32
    .allocstack 32
    .endprolog
    mov rbx, rcx
    test rbx, rbx
    jz gate_fail
    mov rax, [rbx+D2_GATE_FN]
    test rax, rax
    jz gate_fail
    mov rcx, [rbx+D2_GATE_CTX]
    mov rdx, [rbx+D2_GATE_PAYLOAD]
    call rax
    test eax, eax
    jz gate_fail
    mov rdx, [rbx+D2_GATE_OBS_PTR]
    test rdx, rdx
    jz gate_fail
    or dword ptr [rdx], obsbit
    mov eax, 1
    jmp gate_done
gate_fail:
    xor eax, eax
gate_done:
    add rsp, 32
    pop rbx
    ret
procname ENDP
ENDM
