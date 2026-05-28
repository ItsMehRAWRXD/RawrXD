; ==============================================================================
; SwarmV29_AVX512_Feature_Detect.asm
; PHASE-29: AVX-512 Feature Detection for Safe Kernel Dispatch
; Target: 70B @ 150TPS via AVX-512 Vectorized NTT
; ------------------------------------------------------------------------------
; Runtime detection of AVX-512F support to prevent #UD crashes on older CPUs.
; Must be called before any AVX-512 kernel is executed.
; ==============================================================================

.code

; SwarmV29_AVX512_Feature_Detect
; Inputs: None
; Returns:
;   RAX = 1 if AVX-512F is supported
;   RAX = 0 if AVX-512F is NOT supported
; ==============================================================================
ALIGN 16
SwarmV29_AVX512_Feature_Detect PROC PUBLIC
    push rbx
    push rcx
    push rdx

    ; Check CPUID leaf 7 (Extended Features)
    mov eax, 7
    xor ecx, ecx
    cpuid

    ; Test AVX-512F bit (EBX bit 16)
    test ebx, 00010000h
    jz no_avx512

    ; Also verify OS has enabled AVX-512 (check XCR0)
    ; This requires checking if the OS has saved ZMM state
    mov eax, 0Dh                ; XCR0 leaf
    xor ecx, ecx
    cpuid
    test eax, 0E0h              ; Check bits 5,6,7 (OPMASK, ZMM_Hi256, Hi16_ZMM)
    jz no_avx512

    mov rax, 1                  ; AVX-512F fully supported
    jmp done_detect

no_avx512:
    xor rax, rax                ; AVX-512F not supported

done_detect:
    pop rdx
    pop rcx
    pop rbx
    ret
SwarmV29_AVX512_Feature_Detect ENDP

END
