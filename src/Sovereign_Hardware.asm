; ==============================================================================
; Sovereign_Hardware.asm - CPU Feature Detection and Dispatch Initialization
; ==============================================================================

include Sovereign_Common.inc

.CODE

; ----------------------------------------------------------------------------
; Sovereign_Init_Dispatcher
; R13 = Pointer to GOV_STATE
; ----------------------------------------------------------------------------
PUBLIC Sovereign_Init_Dispatcher
Sovereign_Init_Dispatcher PROC
    push rbx
    push rsi
    push rdi
    
    ; 1. Clear Dispatch Table with conservative defaults (scalar/base)
    lea rdi, [r13 + GOV_STATE.dispatch_table]
    mov ecx, (SIZEOF DISPATCH_TABLE) / 8
    xor rax, rax
    rep stosq

    ; Set initial scalar fallbacks
    extern Sovereign_Gemv_F32_Scalar:PROC
    lea rax, Sovereign_Gemv_F32_Scalar
    mov [r13 + GOV_STATE.dispatch_table].DISPATCH_TABLE.pGemv_F32, rax

    ; 2. CPUID Feature Detection
    ; Check for AVX-512F
    mov eax, 7
    xor ecx, ecx
    cpuid
    ; RBX Bit 16 = AVX-512F
    test ebx, 1 SHL 16
    jz @NoAVX512
    
    ; AVX-512 Path
    extern Sovereign_Gemv_F32_AVX512:PROC
    lea rax, Sovereign_Gemv_F32_AVX512
    mov [r13 + GOV_STATE.dispatch_table].DISPATCH_TABLE.pGemv_F32, rax
    jmp @Done

@NoAVX512:
    ; Check for AVX2 + FMA
    mov eax, 7
    xor ecx, ecx
    cpuid
    test ebx, 1 SHL 5 ; AVX2
    jz @NoAVX2
    
    mov eax, 1
    cpuid
    test ecx, 1 SHL 12 ; FMA
    jz @NoAVX2
    
    ; AVX2 Path
    extern Sovereign_Gemv_F32_AVX2:PROC
    lea rax, Sovereign_Gemv_F32_AVX2
    mov [r13 + GOV_STATE.dispatch_table].DISPATCH_TABLE.pGemv_F32, rax
    jmp @Done

@NoAVX2:
    ; Fallback remains Scalar

@Done:
    pop rdi
    pop rsi
    pop rbx
    ret
Sovereign_Init_Dispatcher ENDP

END
