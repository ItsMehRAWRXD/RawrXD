; rawr_native_policy_x64.asm
option casemap:none
include rawr_native_e2e.inc
.code

; R9=mask base, EDX=layer
RN_SetMaskBit proc
    cmp edx, 256
    jae short SMB_Done
    mov eax, edx
    shr eax, 6
    mov ecx, edx
    and ecx, 63
    mov r8, 1
    shl r8, cl
    or qword ptr [r9+rax*8], r8
SMB_Done:
    ret
RN_SetMaskBit endp

; RCX=mask base, EDX=layer -> EAX 0/1
RN_TestMaskBit proc
    cmp edx, 256
    jae short TMB_No
    mov eax, edx
    shr eax, 6
    mov r8, qword ptr [rcx+rax*8]
    mov ecx, edx
    and ecx, 63
    shr r8, cl
    mov eax, r8d
    and eax, 1
    ret
TMB_No:
    xor eax, eax
    ret
RN_TestMaskBit endp

; RCX=profile, RDX=request, R8=out
RawrNative_NormalizePolicy proc public
    push rbx
    push rbp
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub rsp, 28h
    mov r12, rcx
    mov r13, rdx
    mov r14, r8
    test r12, r12
    jz RNP_Fail
    test r13, r13
    jz RNP_Fail
    test r14, r14
    jz RNP_Fail

    xor eax, eax
    mov qword ptr [r14+0], rax
    mov qword ptr [r14+8], rax
    mov qword ptr [r14+16], rax
    mov qword ptr [r14+24], rax
    mov qword ptr [r14+32], rax
    mov qword ptr [r14+40], rax
    mov qword ptr [r14+48], rax
    mov qword ptr [r14+56], rax
    mov qword ptr [r14+64], rax

    mov eax, dword ptr [r13+RNPR_CONTEXT]
    mov dword ptr [r14+RNP_CONTEXT], eax
    mov eax, dword ptr [r13+RNPR_MAX_TOKENS]
    mov dword ptr [r14+RNP_MAX_TOKENS], eax
    mov eax, dword ptr [r13+RNPR_TEMP_MILLI]
    mov dword ptr [r14+RNP_TEMP_MILLI], eax
    mov eax, dword ptr [r13+RNPR_TOP_P_MILLI]
    mov dword ptr [r14+RNP_TOP_P_MILLI], eax
    mov eax, dword ptr [r13+RNPR_TOP_K]
    mov dword ptr [r14+RNP_TOP_K], eax
    mov eax, dword ptr [r13+RNPR_STREAM]
    mov dword ptr [r14+RNP_STREAM], eax

    ; Hard model limits.
    mov eax, dword ptr [r12+RNPI_CONTEXT_MAX]
    test eax, eax
    jz short RNP_MaxTok
    cmp dword ptr [r14+RNP_CONTEXT], eax
    jbe short RNP_MaxTok
    mov dword ptr [r14+RNP_CONTEXT], eax
    or dword ptr [r14+RNP_FLAGS], RN_POLICY_CLAMPED
RNP_MaxTok:
    mov eax, dword ptr [r12+RNPI_MAX_TOKENS]
    test eax, eax
    jz short RNP_Safe
    cmp dword ptr [r14+RNP_MAX_TOKENS], eax
    jbe short RNP_Safe
    mov dword ptr [r14+RNP_MAX_TOKENS], eax
    or dword ptr [r14+RNP_FLAGS], RN_POLICY_CLAMPED

RNP_Safe:
    mov eax, dword ptr [r12+RNPI_ENGINE_MODE]
    test eax, RN_ENGINE_MODE_SAFEDECODE
    jz RNP_Hop
    or dword ptr [r14+RNP_FLAGS], RN_POLICY_SAFE_ELIGIBLE
    cmp dword ptr [r13+RNPR_SAFE_ENABLED], 0
    je RNP_Hop
    or dword ptr [r14+RNP_FLAGS], RN_POLICY_SAFE_PREPARED

    mov eax, dword ptr [r13+RNPR_SAFE_CONTEXT]
    test eax, eax
    jz short RNP_SafeTok
    cmp dword ptr [r14+RNP_CONTEXT], eax
    jbe short RNP_SafeTok
    mov dword ptr [r14+RNP_CONTEXT], eax
    or dword ptr [r14+RNP_FLAGS], RN_POLICY_CLAMPED
RNP_SafeTok:
    mov eax, dword ptr [r13+RNPR_SAFE_MAX_TOKENS]
    test eax, eax
    jz short RNP_SafeTemp
    cmp dword ptr [r14+RNP_MAX_TOKENS], eax
    jbe short RNP_SafeTemp
    mov dword ptr [r14+RNP_MAX_TOKENS], eax
    or dword ptr [r14+RNP_FLAGS], RN_POLICY_CLAMPED
RNP_SafeTemp:
    mov eax, dword ptr [r13+RNPR_SAFE_TEMP_MILLI]
    test eax, eax
    jz short RNP_SafeP
    mov dword ptr [r14+RNP_TEMP_MILLI], eax
RNP_SafeP:
    mov eax, dword ptr [r13+RNPR_SAFE_TOP_P_MILLI]
    test eax, eax
    jz short RNP_SafeK
    mov dword ptr [r14+RNP_TOP_P_MILLI], eax
RNP_SafeK:
    mov eax, dword ptr [r13+RNPR_SAFE_TOP_K]
    test eax, eax
    jz short RNP_Hop
    mov dword ptr [r14+RNP_TOP_K], eax

RNP_Hop:
    mov eax, dword ptr [r12+RNPI_ENGINE_MODE]
    test eax, RN_ENGINE_MODE_TENSORHOP
    jz RNP_Ok
    or dword ptr [r14+RNP_FLAGS], RN_POLICY_HOP_ELIGIBLE
    cmp dword ptr [r13+RNPR_HOP_ENABLED], 0
    je RNP_Ok

    mov eax, dword ptr [r13+RNPR_HOP_STRATEGY]
    mov dword ptr [r14+RNP_HOP_STRATEGY], eax
    cmp eax, RN_HOP_AUTO
    jne short RNP_HopValidate
    or dword ptr [r14+RNP_FLAGS], RN_POLICY_HOP_NEEDS_ENGINE
    jmp RNP_Ok

RNP_HopValidate:
    cmp eax, RN_HOP_CUSTOM
    ja RNP_Fail
    mov ebx, dword ptr [r12+RNPI_NUM_LAYERS]
    test ebx, ebx
    jz RNP_Fail
    cmp ebx, 256
    ja RNP_Fail
    mov esi, dword ptr [r13+RNPR_HOP_KEEP_FIRST]
    mov edi, dword ptr [r13+RNPR_HOP_KEEP_LAST]
    mov eax, esi
    add eax, edi
    cmp eax, ebx
    ja RNP_Fail
    mov ebp, ebx
    sub ebp, esi
    sub ebp, edi
    test ebp, ebp
    jz RNP_Ok

    mov eax, dword ptr [r13+RNPR_HOP_SKIP_PERMILLE]
    cmp eax, 500
    ja RNP_Fail
    imul eax, ebp
    xor edx, edx
    mov ecx, 1000
    div ecx
    mov r15d, eax
    lea r9, [r14+RNP_HOP_MASK]
    xor r11d, r11d
    test r15d, r15d
    jz RNP_HopPrepared

    mov eax, dword ptr [r13+RNPR_HOP_STRATEGY]
    cmp eax, RN_HOP_FRONT
    je RNP_Front
    cmp eax, RN_HOP_BACK
    je RNP_Back
    cmp eax, RN_HOP_CUSTOM
    je RNP_Custom

    xor r10d, r10d
    mov edx, esi
RNP_EvenLoop:
    mov eax, ebx
    sub eax, edi
    cmp edx, eax
    jae short RNP_HopCountDone
    add r10d, r15d
    cmp r10d, ebp
    jb short RNP_EvenNext
    sub r10d, ebp
    call RN_SetMaskBit
    inc r11d
RNP_EvenNext:
    inc edx
    jmp RNP_EvenLoop

RNP_Front:
    mov edx, esi
RNP_FrontLoop:
    cmp r11d, r15d
    jae short RNP_HopCountDone
    call RN_SetMaskBit
    inc edx
    inc r11d
    jmp RNP_FrontLoop

RNP_Back:
    mov edx, ebx
    sub edx, edi
RNP_BackLoop:
    cmp r11d, r15d
    jae short RNP_HopCountDone
    dec edx
    call RN_SetMaskBit
    inc r11d
    jmp RNP_BackLoop

RNP_Custom:
    mov edx, esi
RNP_CustomLoop:
    mov eax, ebx
    sub eax, edi
    cmp edx, eax
    jae short RNP_HopCountDone
    lea rcx, [r13+RNPR_CUSTOM_MASK]
    call RN_TestMaskBit
    test eax, eax
    jz short RNP_CustomNext
    call RN_SetMaskBit
    inc r11d
RNP_CustomNext:
    inc edx
    jmp RNP_CustomLoop

RNP_HopCountDone:
    mov dword ptr [r14+RNP_HOP_SKIP_COUNT], r11d
RNP_HopPrepared:
    or dword ptr [r14+RNP_FLAGS], RN_POLICY_HOP_PREPARED
RNP_Ok:
    xor eax, eax
    jmp short RNP_Done
RNP_Fail:
    mov eax, 1
RNP_Done:
    add rsp, 28h
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    ret
RawrNative_NormalizePolicy endp
end
