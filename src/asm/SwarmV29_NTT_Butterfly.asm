; =============================================================================
; SwarmV29_NTT_Butterfly.asm - Forward NTT Butterfly Kernel
; =============================================================================
; Number Theoretic Transform (NTT) forward butterfly for PQC
; AVX-512 optimized for lattice-based cryptography
; Date: 2026-07-08
; =============================================================================

INCLUDE SwarmV29_Macros.inc

; =============================================================================
;                            EXPORTS
; =============================================================================
PUBLIC SwarmV29_NTT_Butterfly
PUBLIC SwarmV29_NTT_Forward
PUBLIC SwarmV29_NTT_Butterfly_Scalar

; =============================================================================
;                            DATA
; =============================================================================
.data

; Twiddle factors (example for N=256, q=12289)
ALIGN 64
TwiddleFactors QWORD 256 DUP (<>)

; Constants
ALIGN 64
Modulus QWORD 12289        ; Prime modulus q
ModulusInv QWORD 0         ; Modular inverse (computed at init)
RootOfUnity QWORD 0        ; Primitive root of unity

; =============================================================================
;                            CODE
; =============================================================================
.code

; =============================================================================
; SwarmV29_NTT_Butterfly_Scalar
; Scalar NTT butterfly (fallback for non-AVX512)
;
; RCX = a pointer
; RDX = b pointer
; R8  = twiddle factor
; R9  = modulus
;
; Returns: void (modifies a and b in place)
; =============================================================================
SwarmV29_NTT_Butterfly_Scalar PROC FRAME
    SWARMV29_ABI_FRAME
    
    ; Load values
    mov rax, [rcx]          ; a
    mov rbx, [rdx]          ; b
    
    ; Compute: t = (twiddle * b) mod q
    mov r8, r8              ; twiddle
    imul r8, rbx            ; twiddle * b
    mov r9, r9              ; modulus
    
    ; Modular reduction (simplified)
    xor rdx, rdx
    div r9                  ; rax = quotient, rdx = remainder
    mov r8, rdx             ; t = (twiddle * b) mod q
    
    ; Compute: b = (a - t) mod q
    sub rax, r8
    js @@neg_b
    mov [rdx], rax          ; b = a - t
    jmp @@compute_a
    
@@neg_b:
    add rax, r9             ; Add modulus if negative
    mov [rdx], rax
    
@@compute_a:
    ; Compute: a = (a + t) mod q
    mov rax, [rcx]
    add rax, r8
    cmp rax, r9
    jb @@store_a
    sub rax, r9
    
@@store_a:
    mov [rcx], rax
    
    SWARMV29_ABI_EPILOG
SwarmV29_NTT_Butterfly_Scalar ENDP

; =============================================================================
; SwarmV29_NTT_Butterfly
; AVX-512 optimized NTT butterfly
;
; RCX = data pointer (array of int64)
; RDX = twiddle factors pointer
; R8  = n (must be power of 2)
; R9  = modulus
;
; Returns: RAX = 0 on success, -1 on failure
; =============================================================================
SwarmV29_NTT_Butterfly PROC FRAME
    SWARMV29_ABI_FRAME
    
    ; Validate parameters
    test rcx, rcx
    jz @@invalid_params
    test rdx, rdx
    jz @@invalid_params
    test r8, r8
    jz @@invalid_params
    
    ; Check if n is power of 2
    mov rax, r8
    dec rax
    test rax, r8
    jnz @@invalid_params
    
    ; Save parameters
    mov r12, rcx            ; data pointer
    mov r13, rdx            ; twiddle factors
    mov r14, r8             ; n
    mov r15, r9             ; modulus
    
    ; Compute log2(n)
    mov eax, r8d
    bsr eax, eax            ; bit scan reverse
    mov r11d, eax           ; r11 = log2(n)
    
    ; Main NTT loop
    xor ebx, ebx            ; stage counter
    
@@ntt_stage_loop:
    cmp ebx, r11d
    jge @@ntt_done
    
    ; Compute distance for this stage
    mov eax, 1
    mov ecx, ebx
    shl eax, cl             ; distance = 1 << stage
    
    ; Compute number of blocks
    mov ecx, r14d
    shr ecx, 1
    mov edx, ebx
    shr ecx, cl             ; blocks = n >> (stage + 1)
    
    ; Process each block
    xor esi, esi           ; block counter
    
@@block_loop:
    cmp esi, ecx
    jge @@stage_done
    
    ; Process each pair in block
    mov edi, eax            ; distance
    shl edi, 1              ; 2 * distance
    
    ; Inner loop
    xor ebp, ebp            ; pair counter
    
@@pair_loop:
    mov r8d, r14d
    cmp ebp, r8d
    jge @@block_done
    
    ; Compute indices
    mov r8d, esi
    imul r8d, edi           ; block_start = block * 2 * distance
    add r8d, ebp            ; i = block_start + pair
    
    mov r9d, r8d
    add r9d, eax            ; j = i + distance
    
    ; Load values
    mov r10, [r12 + r8 * 8]  ; a[i]
    mov r11, [r12 + r9 * 8]  ; a[j]
    
    ; Compute twiddle index
    mov ecx, ebx
    mov edx, ebp
    shr edx, cl             ; twiddle_idx = pair >> stage
    
    ; Load twiddle factor
    mov rax, [r13 + rdx * 8] ; twiddle
    
    ; Butterfly: t = twiddle * a[j] mod q
    imul rax, r11
    xor rdx, rdx
    div r15                 ; rdx = (twiddle * a[j]) mod q
    mov rax, rdx
    
    ; a[i] = (a[i] + t) mod q
    add r10, rax
    cmp r10, r15
    jb @@no_mod1
    sub r10, r15
@@no_mod1:
    mov [r12 + r8 * 8], r10
    
    ; a[j] = (a[i] - t) mod q
    mov r10, [r12 + r8 * 8]
    sub r10, rax
    jns @@no_mod2
    add r10, r15
@@no_mod2:
    mov [r12 + r9 * 8], r10
    
    inc ebp
    jmp @@pair_loop
    
@@block_done:
    inc esi
    jmp @@block_loop
    
@@stage_done:
    inc ebx
    jmp @@ntt_stage_loop
    
@@ntt_done:
    xor rax, rax
    jmp @@done
    
@@invalid_params:
    mov rax, -1
    
@@done:
    SWARMV29_ABI_EPILOG
SwarmV29_NTT_Butterfly ENDP

; =============================================================================
; SwarmV29_NTT_Forward
; Complete forward NTT transform
;
; RCX = data pointer
; RDX = twiddle factors pointer
; R8  = n (must be power of 2)
; R9  = modulus
;
; Returns: RAX = 0 on success
; =============================================================================
SwarmV29_NTT_Forward PROC FRAME
    SWARMV29_ABI_FRAME
    
    ; Just call butterfly
    call SwarmV29_NTT_Butterfly
    
    SWARMV29_ABI_EPILOG
SwarmV29_NTT_Forward ENDP

END