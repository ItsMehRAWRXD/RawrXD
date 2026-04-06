OPTION CASEMAP:NONE

EXTERN QueryPerformanceCounter:PROC

CPU_FEATURE_AVX512 EQU 1
CPU_FEATURE_AVX2   EQU 2
CPU_FEATURE_SSE41  EQU 4

.code

PUBLIC rawrxd_recovery_stub_ai_agent_masm_core
PUBLIC masm_get_performance_counter
PUBLIC masm_get_cpu_features
PUBLIC masm_memory_scan_pattern_avx512

; Compatibility entry point retained for older recovery probes.
rawrxd_recovery_stub_ai_agent_masm_core PROC FRAME
    .endprolog
    mov eax, 1
    ret
rawrxd_recovery_stub_ai_agent_masm_core ENDP

; uint64_t masm_get_performance_counter(void)
masm_get_performance_counter PROC FRAME
    sub rsp, 28h
    .allocstack 28h
    .endprolog

    lea rcx, [rsp+20h]
    call QueryPerformanceCounter
    test eax, eax
    jz perf_counter_failed

    mov rax, qword ptr [rsp+20h]
    add rsp, 28h
    ret

perf_counter_failed:
    xor eax, eax
    add rsp, 28h
    ret
masm_get_performance_counter ENDP

; uint64_t masm_get_cpu_features(void)
masm_get_cpu_features PROC FRAME
    push rbx
    .pushreg rbx
    .endprolog

    xor r10d, r10d

    mov eax, 0
    cpuid
    mov r11d, eax

    cmp r11d, 1
    jb cpu_features_done

    mov eax, 1
    xor ecx, ecx
    cpuid
    bt ecx, 19
    jnc check_leaf7
    or r10d, CPU_FEATURE_SSE41

check_leaf7:
    cmp r11d, 7
    jb cpu_features_done

    mov eax, 7
    xor ecx, ecx
    cpuid
    bt ebx, 5
    jnc check_avx512
    or r10d, CPU_FEATURE_AVX2

check_avx512:
    bt ebx, 16
    jnc cpu_features_done
    or r10d, CPU_FEATURE_AVX512

cpu_features_done:
    mov eax, r10d
    pop rbx
    ret
masm_get_cpu_features ENDP

; uint64_t masm_memory_scan_pattern_avx512(const void* buffer, size_t buffer_size, const MasmBytePattern* pattern)
; Scalar implementation for now; exported from MASM so the live bridge no longer depends on the C++ scaffold.
; RCX=buffer, RDX=buffer_size, R8=pattern
masm_memory_scan_pattern_avx512 PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    push r12
    .pushreg r12
    push r13
    .pushreg r13
    push r14
    .pushreg r14
    push r15
    .pushreg r15
    .endprolog

    xor eax, eax
    test rcx, rcx
    jz scan_return
    test r8, r8
    jz scan_return

    mov r11, qword ptr [r8+8]      ; pattern_length
    test r11, r11
    jz zero_matches
    cmp rdx, r11
    jb zero_matches

    mov r9, qword ptr [r8]         ; pattern bytes
    test r9, r9
    jz zero_matches

    mov r10, qword ptr [r8+18h]    ; mask pointer
    mov r12, rcx                   ; buffer base
    mov r13, rdx                   ; buffer size
    sub r13, r11
    inc r13                        ; scan limit count
    xor r14, r14                   ; match count
    xor r15, r15                   ; outer index

outer_loop:
    cmp r15, r13
    jae scan_done

    xor rbx, rbx                   ; inner index

inner_loop:
    cmp rbx, r11
    jae matched_pattern

    test r10, r10
    jz compare_byte

    mov al, byte ptr [r10+rbx]
    cmp al, '?'
    je next_byte

compare_byte:
    lea rsi, [r12+r15]
     mov al, byte ptr [rsi+rbx]
    cmp al, byte ptr [r9+rbx]
    jne no_match

next_byte:
    inc rbx
    jmp inner_loop

matched_pattern:
    inc r14

no_match:
    inc r15
    jmp outer_loop

zero_matches:
    xor r14, r14

scan_done:
    mov qword ptr [r8+20h], r14    ; pattern->matches_found
    mov rax, r14

scan_return:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
masm_memory_scan_pattern_avx512 ENDP

END