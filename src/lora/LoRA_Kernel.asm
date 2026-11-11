; ==============================================================================
; LoRA_Kernel.asm - High-Performance Vector Update
; Signature: void ApplyLoRA_VectorAdd(float* a, float* b, float* dest, size_t count);
; ==============================================================================

.code

ApplyLoRA_VectorAdd PROC FRAME
    ; 1. Stack Frame Setup (Windows x64 ABI)
    push    rbp             ; Save non-volatile base pointer
    .pushreg rbp
    mov     rbp, rsp        ; Establish frame
    .setframe rbp, 0
    sub     rsp, 32         ; Allocate Shadow Space (mandatory)
    .allocstack 32
    .endprolog

    ; 2. Register mapping
    ; RCX = a (src)
    ; RDX = b (scale/add)
    ; R8  = dest (out)
    ; R9  = count
    
    ; Save non-volatile registers we'll use
    mov     [rbp-8], rbx
    mov     [rbp-16], rdi
    mov     [rbp-24], rsi
    
    ; Setup loop counters
    mov     rbx, r9         ; RBX = count
    xor     rdi, rdi        ; RDI = index = 0
    shr     rbx, 3          ; Divide count by 8 (processing 8 floats per YMM register)
    jz      HandleRemainder ; If count < 8, skip AVX block

LoopAVX:
    vmovups ymm0, [rcx + rdi*4] ; Load 8 floats from a
    vmovups ymm1, [rdx + rdi*4] ; Load 8 floats from b
    vaddps  ymm0, ymm0, ymm1    ; ymm0 = a + b
    vmovups [r8 + rdi*4], ymm0  ; Store 8 floats to dest
    
    add     rdi, 8          ; Advance index
    dec     rbx             ; Decrement loop counter
    jnz     LoopAVX         ; Jump if not done

HandleRemainder:
    ; Calculate remaining elements: count & 7
    mov     rbx, r9
    and     rbx, 7          ; RBX = count % 8
    jz      Cleanup         ; If no remainder, done
    
    ; Process remaining elements (scalar)
RemainderLoop:
    movss   xmm0, dword ptr [rcx + rdi*4]  ; Load float from a
    movss   xmm1, dword ptr [rdx + rdi*4]  ; Load float from b
    addss   xmm0, xmm1                     ; xmm0 = a + b
    movss   dword ptr [r8 + rdi*4], xmm0   ; Store to dest
    
    inc     rdi             ; Advance index
    dec     rbx             ; Decrement counter
    jnz     RemainderLoop   ; Continue if more elements
    
Cleanup:
    vzeroupper              ; Clear YMM registers (AVX-SSE transition)
    
    ; Restore non-volatile registers
    mov     rbx, [rbp-8]
    mov     rdi, [rbp-16]
    mov     rsi, [rbp-24]
    
    mov     rsp, rbp        ; Restore stack
    pop     rbp             ; Restore base pointer
    ret                     ; Return
ApplyLoRA_VectorAdd ENDP

END
