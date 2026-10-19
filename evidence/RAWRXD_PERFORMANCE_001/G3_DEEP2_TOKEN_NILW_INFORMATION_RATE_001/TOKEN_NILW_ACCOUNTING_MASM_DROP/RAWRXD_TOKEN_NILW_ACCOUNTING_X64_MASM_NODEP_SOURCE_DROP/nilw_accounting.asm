option casemap:none
include nilw_accounting.inc

.code
PUBLIC NilwEvaluate

NilwEvaluate PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    sub rsp,20h
    .allocstack 20h
    .endprolog
    mov rsi,rcx
    mov rbx,rdx
    test rbx,rbx
    jz ne_null_output

    mov rdi,rbx
    xor eax,eax
    mov ecx,SIZEOF NILW_RESULT / 8
    cld
    rep stosq
    test rsi,rsi
    jnz short ne_validate
    mov [rbx].NILW_RESULT.status,NILW_E_NULL
    mov [rbx].NILW_RESULT.error_mask,NILW_ERR_NULL_INPUT
    mov eax,NILW_E_NULL
    jmp short ne_done

ne_validate:
    mov rcx,rsi
    mov rdx,rbx
    call NilwValidateShape
    test eax,eax
    jnz short ne_done
    mov rcx,rsi
    mov rdx,rbx
    call NilwDeriveExact
    test eax,eax
    jnz short ne_done
    mov rcx,rsi
    mov rdx,rbx
    call NilwApplyPerformanceGates
    mov rcx,rsi
    mov rdx,rbx
    call NilwApplyAuthorityGates
    xor eax,eax
    jmp short ne_done

ne_null_output:
    mov eax,NILW_E_NULL
ne_done:
    add rsp,20h
    pop rdi
    pop rsi
    pop rbx
    ret
NilwEvaluate ENDP

END
