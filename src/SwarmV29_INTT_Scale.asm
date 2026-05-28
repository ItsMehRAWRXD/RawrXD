; SwarmV29 INTT Scale — Final Scaling Pass for Inverse NTT
; Production-hardened, AVX-512, Montgomery domain arithmetic
; Assemble: ml64.exe /c /Cx /W3 /nologo /Zi /Fo SwarmV29_INTT_Scale.obj SwarmV29_INTT_Scale.asm
; No CRT, no dependencies, 64-byte cache alignment
;
; Architecture:
;   After all INTT butterfly stages, each coefficient must be scaled by N^-1 mod Q.
;   This kernel performs a single linear pass over the coefficient buffer.
;   Uses Montgomery multiplication for efficient modular arithmetic.
;
; Mathematical Operation:
;   For each coefficient c_i: c_i' = c_i * N^-1 mod Q
;
; Inputs:
;   RCX = Buffer Pointer (64-byte aligned)
;   RDX = Vector Size (number of coefficients, must be multiple of 8)
;   R8  = N_INV (modular inverse of N)
;   R9  = Q (modulus)
;   [RSP+40] = Q_INV (Montgomery constant)
;
; Outputs:
;   Buffer is modified in-place with scaled coefficients

OPTION CASEMAP:NONE

.DATA
    ALIGN 16
    
    ; Pre-computed constants (set at initialization)
    PUBLIC SwarmV29_Scale_Q
    SwarmV29_Scale_Q QWORD 0
    
    PUBLIC SwarmV29_Scale_Q_INV
    SwarmV29_Scale_Q_INV QWORD 0
    
    PUBLIC SwarmV29_Scale_N_INV
    SwarmV29_Scale_N_INV QWORD 0
    
    ; 32-bit mask for Montgomery reduction
    ALIGN 16
    mask_32bit DQ 0FFFFFFFFh
               DQ 0FFFFFFFFh
               DQ 0FFFFFFFFh
               DQ 0FFFFFFFFh
               DQ 0FFFFFFFFh
               DQ 0FFFFFFFFh
               DQ 0FFFFFFFFh
               DQ 0FFFFFFFFh

.CODE

; ==============================================================================
; SwarmV29_INTT_Scale
; Scales all coefficients by N^-1 mod Q (Montgomery domain)
; 
; This is the final pass after all INTT butterfly stages.
; Processes 8 coefficients per iteration (512 bits = 1 ZMM register).
;
; Register Usage:
;   zmm10 = N_INV (broadcast)
;   zmm15 = Q (broadcast)
;   zmm16 = Q_INV (broadcast)
;   zmm0-zmm5 = Computation (volatile)
; ==============================================================================
ALIGN 16
PUBLIC SwarmV29_INTT_Scale
SwarmV29_INTT_Scale PROC
    push rbp
    mov rbp, rsp
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    
    ; Save parameters
    mov rsi, rcx                ; rsi = buffer pointer
    mov rdi, rdx                ; rdi = vector size (count)
    mov r12, r8                 ; r12 = N_INV
    mov r13, r9                 ; r13 = Q
    
    ; Broadcast constants into ZMM registers (reused across all iterations)
    vpbroadcastq zmm10, r12     ; zmm10 = N_INV (broadcast)
    vpbroadcastq zmm15, r13     ; zmm15 = Q (broadcast)
    
    ; Load Q_INV from stack
    mov rax, [rsp + 40 + 48]    ; Adjusted for pushed registers
    vpbroadcastq zmm16, rax     ; zmm16 = Q_INV (broadcast)
    
    ; Load 32-bit mask for Montgomery reduction
    vmovdqa64 zmm17, [mask_32bit]

; ==============================================================================
; Main Scaling Loop
; Process 8 coefficients per iteration (512 bits = 1 ZMM register)
; ==============================================================================
ALIGN 16
Scale_Loop:
    cmp rdi, 8
    jl Scale_Done
    
    ; Load 8 coefficients (64 bytes)
    vmovdqa64 zmm0, [rsi]
    
    ; =========================================================================
    ; Montgomery Multiply: c_i * N_INV mod Q
    ; Using simplified Montgomery reduction (same pattern as INTT_Butterfly)
    ; =========================================================================
    
    ; T = c_i * N_INV (low 64 bits)
    vpmullq zmm1, zmm0, zmm10
    
    ; m = T * Q_INV (low 32 bits only for reduction)
    vpmullq zmm3, zmm1, zmm16
    
    ; m mod 2^32 (mask to low 32 bits)
    vpandq zmm3, zmm3, zmm17
    
    ; m * Q
    vpmullq zmm4, zmm3, zmm15
    
    ; T + m*Q
    vpaddq zmm5, zmm1, zmm4
    
    ; result = (T + m*Q) >> 32
    vpsrlq zmm5, zmm5, 32
    
    ; =========================================================================
    ; Normalization: Handle Q overflow
    ; Branchless conditional subtract using AVX-512 masking
    ; =========================================================================
    
    ; Create mask for values >= Q (need reduction)
    vpcmpgtq k1, zmm5, zmm15
    
    ; Conditionally subtract Q where mask is true
    vpsubq zmm5 {k1}, zmm5, zmm15
    
    ; Store 8 scaled coefficients
    vmovdqa64 [rsi], zmm5
    
    ; Advance pointer and decrement counter
    add rsi, 64                 ; 8 coefficients * 8 bytes = 64 bytes
    sub rdi, 8
    jmp Scale_Loop

Scale_Done:
    ; Memory fence to ensure all stores are globally visible
    ; This is critical for multi-threaded PQC operations
    sfence
    
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret
SwarmV29_INTT_Scale ENDP

; ==============================================================================
; SwarmV29_INTT_Scale_Init
; Initialize scaling constants
; RCX = Q (modulus)
; RDX = Q_INV (Montgomery inverse)
; R8  = N_INV (degree inverse)
; ==============================================================================
ALIGN 16
PUBLIC SwarmV29_INTT_Scale_Init
SwarmV29_INTT_Scale_Init PROC
    mov qword ptr [SwarmV29_Scale_Q], rcx
    mov qword ptr [SwarmV29_Scale_Q_INV], rdx
    mov qword ptr [SwarmV29_Scale_N_INV], r8
    ret
SwarmV29_INTT_Scale_Init ENDP

; ==============================================================================
; SwarmV29_INTT_Scale_Get_Constants
; Retrieve scaling constants (for debugging/telemetry)
; RAX = Q, RDX = Q_INV, R8 = N_INV (returned via registers)
; ==============================================================================
ALIGN 16
PUBLIC SwarmV29_INTT_Scale_Get_Constants
SwarmV29_INTT_Scale_Get_Constants PROC
    mov rax, [SwarmV29_Scale_Q]
    mov rdx, [SwarmV29_Scale_Q_INV]
    mov r8, [SwarmV29_Scale_N_INV]
    ret
SwarmV29_INTT_Scale_Get_Constants ENDP

END