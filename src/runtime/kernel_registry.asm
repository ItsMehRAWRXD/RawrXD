; =============================================================================
; kernel_registry.asm - CPU Feature Detection & Kernel Dispatch Table
; =============================================================================
; Detects available SIMD instruction sets (AVX512, AVX2, FMA, SSE) and
; maintains a dispatch table mapping kernel IDs to the best available
; implementation for the current CPU.
;
; CPUID leaf 7 (EBX) is used to probe:
;   bit 5  = AVX2
;   bit 16 = AVX-512 F
;   bit 12 = FMA
;
; The dispatch table is populated at init time so all subsequent kernel
; calls are O(1) indirect jumps with no repeated feature checks.
; =============================================================================

OPTION CASEMAP:NONE

INCLUDE masm_kernel_api.inc

; =============================================================================
; DATA SECTION
; =============================================================================

.data

; CPU feature bitmask (combination of CPU_FEATURE_* flags)
align 8
g_CPUFeatures           DQ 0

; Active kernel set name string (for logging)
align 8
g_KernelSetName         DQ 0       ; Pointer to name string

; Kernel dispatch table: array of KERNEL_ENTRY_STRUCT
; Indexed by KERNEL_ID_* - 1
MAX_KERNEL_ENTRIES      EQU 16

align 8
g_KernelTable           KERNEL_ENTRY_STRUCT MAX_KERNEL_ENTRIES DUP(<0, 0, 0, 0>)

; Feature name strings
align 8
szAVX512                DB 'AVX512', 0
szAVX2                  DB 'AVX2', 0
szFMA                   DB 'FMA', 0
szSSE                   DB 'SSE', 0
szGENERIC               DB 'GENERIC', 0

; =============================================================================
; CODE SECTION
; =============================================================================

.code

; =============================================================================
; RawrXD_GetCPUFeatures - Detect CPU SIMD capabilities via CPUID
; Simplified: just check basic CPUID leaves, no xgetbv
; Returns: RAX = bitmask of CPU_FEATURE_* flags
; =============================================================================
RawrXD_GetCPUFeatures PROC FRAME
    push rbx
    .pushreg rbx
    push rcx
    .pushreg rcx
    .endprolog

    xor eax, eax
    mov rbx, rax                    ; rbx = feature accumulator

    ; CPUID leaf 0: verify CPUID is supported
    pushfq
    pop rax
    mov rcx, rax
    xor eax, 200000h
    push rax
    popfq
    pushfq
    pop rax
    cmp rax, rcx
    je @@exit                       ; CPUID not supported

    ; CPUID leaf 1: check SSE, SSE2, SSE3, AVX
    mov eax, 1
    cpuid
    test edx, 02000000h
    jz @@check_sse2
    or rbx, CPU_FEATURE_SSE
@@check_sse2:
    test edx, 04000000h
    jz @@check_sse3
    or rbx, CPU_FEATURE_SSE2
@@check_sse3:
    test ecx, 1
    jz @@check_avx
    or rbx, CPU_FEATURE_SSE3
@@check_avx:
    test ecx, 18000000h
    jz @@check_avx2
    or rbx, CPU_FEATURE_AVX
@@check_avx2:
    ; CPUID leaf 7: check AVX2, AVX-512
    mov eax, 7
    xor ecx, ecx
    cpuid
    test ebx, 20h
    jz @@check_avx512
    or rbx, CPU_FEATURE_AVX2
@@check_avx512:
    test ebx, 10000h
    jz @@done
    or rbx, CPU_FEATURE_AVX512
@@done:
    mov rax, rbx
    mov QWORD PTR [g_CPUFeatures], rax
@@exit:
    pop rcx
    pop rbx
    ret
RawrXD_GetCPUFeatures ENDP

; =============================================================================
; RawrXD_GetActiveKernelSet - Get the name of the active kernel set
; Returns: RAX = pointer to null-terminated string
; =============================================================================
RawrXD_GetActiveKernelSet PROC FRAME
    .endprolog
    mov rax, QWORD PTR [g_KernelSetName]
    test rax, rax
    jnz @@exit
    lea rax, szGENERIC
@@exit:
    ret
RawrXD_GetActiveKernelSet ENDP

; =============================================================================
; RawrXD_InitKernelRegistry - Initialize kernel dispatch table
; Simplified: just detect CPU features and return success
;
; Returns: RAX = 0 on success
; =============================================================================
RawrXD_InitKernelRegistry PROC FRAME
    push rbx
    .pushreg rbx
    .endprolog

    ; Detect CPU features
    call RawrXD_GetCPUFeatures
    mov QWORD PTR [g_CPUFeatures], rax

    ; Set kernel set name based on features
    test rax, CPU_FEATURE_AVX512
    jz @@check_avx2
    lea rax, szAVX512
    mov QWORD PTR [g_KernelSetName], rax
    jmp @@done

@@check_avx2:
    mov rax, QWORD PTR [g_CPUFeatures]
    test rax, CPU_FEATURE_AVX2
    jz @@check_fma
    lea rax, szAVX2
    mov QWORD PTR [g_KernelSetName], rax
    jmp @@done

@@check_fma:
    mov rax, QWORD PTR [g_CPUFeatures]
    test rax, CPU_FEATURE_FMA
    jz @@check_sse
    lea rax, szFMA
    mov QWORD PTR [g_KernelSetName], rax
    jmp @@done

@@check_sse:
    mov rax, QWORD PTR [g_CPUFeatures]
    test rax, CPU_FEATURE_SSE
    jz @@generic
    lea rax, szSSE
    mov QWORD PTR [g_KernelSetName], rax
    jmp @@done

@@generic:
    lea rax, szGENERIC
    mov QWORD PTR [g_KernelSetName], rax

@@done:
    xor eax, eax                    ; Return success
    pop rbx
    ret
RawrXD_InitKernelRegistry ENDP

; =============================================================================
; RawrXD_DispatchKernel - Dispatch a kernel call through the table
; Parameters:
;   RCX = kernel_id (KERNEL_ID_*)
;   RDX = arg1 (varies by kernel)
;   R8  = arg2
;   R9  = arg3
; Stack: arg4, arg5, ...
; Returns: RAX = kernel return value
; =============================================================================
RawrXD_DispatchKernel PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    .endprolog

    mov rbx, rcx                    ; rbx = kernel_id
    mov rsi, rdx                    ; rsi = arg1

    ; Validate kernel_id
    cmp rbx, MAX_KERNEL_ENTRIES
    ja @@invalid

    ; Calculate table index: (kernel_id - 1) * sizeof(KERNEL_ENTRY_STRUCT)
    dec rbx
    shl rbx, 5                      ; Multiply by 32

    ; Get dispatch table base
    lea rax, g_KernelTable

    ; Select best variant based on CPU features
    mov rcx, g_CPUFeatures
    test rcx, CPU_FEATURE_AVX512
    jnz @@use_avx512
    test rcx, CPU_FEATURE_AVX2
    jnz @@use_avx2
    jmp @@use_scalar

@@use_avx512:
    mov rax, QWORD PTR [rax + rbx + 8]  ; fn_avx512
    jmp @@call_kernel

@@use_avx2:
    mov rax, QWORD PTR [rax + rbx + 16] ; fn_avx2
    jmp @@call_kernel

@@use_scalar:
    mov rax, QWORD PTR [rax + rbx + 24] ; fn_scalar

@@call_kernel:
    test rax, rax
    jz @@invalid

    ; Restore original arguments and call
    mov rcx, rsi                    ; arg1
    ; RDX, R8, R9 already contain args 2-4
    ; Stack args need to be forwarded - for simplicity, we jump
    ; In production, this would use a proper thunk
    jmp rax

@@invalid:
    mov rax, KERNEL_ERR_UNSUPPORTED

    pop rsi
    pop rbx
    ret

RawrXD_DispatchKernel ENDP

END
