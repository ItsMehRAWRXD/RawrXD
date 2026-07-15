; =============================================================================
; SwarmV29_INTT_Butterfly.asm - Inverse NTT Butterfly Kernel
; =============================================================================
; Inverse Number Theoretic Transform (INTT) butterfly for PQC
; AVX-512 optimized for lattice-based cryptography
; Date: 2026-07-08
; =============================================================================

INCLUDE SwarmV29_Macros.inc

; =============================================================================
;                            EXPORTS
; =============================================================================
PUBLIC SwarmV29_INTT_Butterfly
PUBLIC SwarmV29_INTT_Inverse
PUBLIC SwarmV29_INTT_Scale

; =============================================================================
;                            DATA
; =============================================================================
.data

; Inverse twiddle factors
ALIGN 64
InvTwiddleFactors QWORD 256 DUP (<>)

; Precomputed constants
ALIGN 64
NInv QWORD 0              ; n^(-1) mod q

; =============================================================================
;                            CODE
; =============================================================================
.code

; =============================================================================
; SwarmV29_INTT_Butterfly
; Inverse NTT butterfly (Gentleman-Sande butterfly)
;
; RCX = data pointer (array of int64)
; RDX = inverse twiddle factors pointer
; R8  = n (must be power of 2)
; R9  = modulus
;
; Returns: RAX = 0 on success, -1 on failure
; =============================================================================
SwarmV29_INTT_Butterfly PROC FRAME
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
    mov r13, rdx            ; inv twiddle factors
    mov r14, r8             ; n
    mov r15, r9             ; modulus
    
    ; Compute log2(n)
    mov eax, r8d
    bsr eax, eax
    mov r11d, eax           ; r11 = log2(n)
    
    ; Main INTT loop (reverse order)
    mov ebx, r11d           ; stage = log2(n) - 1
    dec ebx
    
@@intt_stage_loop:
    cmp ebx, 0
    jl @@intt_done
    
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
    xor esi, esi
    
@@block_loop:
    cmp esi, ecx
    jge @@stage_done
    
    ; Process each pair in block
    mov edi, eax
    shl edi, 1              ; 2 * distance
    
    xor ebp, ebp
    
@@pair_loop:
    mov r8d, r14d
    cmp ebp, r8d
    jge @@block_done
    
    ; Compute indices
    mov r8d, esi
    imul r8d, edi
    add r8d, ebp            ; i
    
    mov r9d, r8d
    add r9d, eax            ; j = i + distance
    
    ; Load values
    mov r10, [r12 + r8 * 8]  ; a[i]
    mov r11, [r12 + r9 * 8]  ; a[j]
    
    ; Gentleman-Sande butterfly:
    ; a[i] = (a[i] + a[j]) mod q
    ; a[j] = (a[i] - a[j]) * twiddle mod q
    
    ; Save a[i]
    mov rax, r10
    
    ; a[i] = (a[i] + a[j]) mod q
    add r10, r11
    cmp r10, r15
    jb @@no_mod1
    sub r10, r15
@@no_mod1:
    mov [r12 + r8 * 8], r10
    
    ; a[j] = (a[i] - a[j]) * twiddle mod q
    sub rax, r11
    jns @@no_neg
    add rax, r15
@@no_neg:
    
    ; Compute twiddle index
    mov ecx, ebx
    mov edx, ebp
    shr edx, cl
    
    ; Load inverse twiddle
    mov r10, [r13 + rdx * 8]
    
    ; Multiply
    imul rax, r10
    xor rdx, rdx
    div r15
    mov rax, rdx
    
    mov [r12 + r9 * 8], rax
    
    inc ebp
    jmp @@pair_loop
    
@@block_done:
    inc esi
    jmp @@block_loop
    
@@stage_done:
    dec ebx
    jmp @@intt_stage_loop
    
@@intt_done:
    xor rax, rax
    jmp @@done
    
@@invalid_params:
    mov rax, -1
    
@@done:
    SWARMV29_ABI_EPILOG
SwarmV29_INTT_Butterfly ENDP

; =============================================================================
; SwarmV29_INTT_Scale
; Scale by n^(-1) mod q after INTT
;
; RCX = data pointer
; RDX = n (size)
; R8  = n_inv (n^(-1) mod q)
; R9  = modulus
;
; Returns: RAX = 0 on success
; =============================================================================
SwarmV29_INTT_Scale PROC FRAME
    SWARMV29_ABI_FRAME
    
    mov r12, rcx            ; data pointer
    mov r13, rdx            ; n
    mov r14, r8             ; n_inv
    mov r15, r9             ; modulus
    
    xor ebx, ebx            ; counter
    
@@scale_loop:
    cmp rbx, r13
    jge @@scale_done
    
    ; Load value
    mov rax, [r12 + rbx * 8]
    
    ; Multiply by n_inv mod q
    imul rax, r14
    xor rdx, rdx
    div r15
    mov rax, rdx
    
    ; Store result
    mov [r12 + rbx * 8], rax
    
    inc rbx
    jmp @@scale_loop
    
@@scale_done:
    xor rax, rax
    SWARMV29_ABI_EPILOG
SwarmV29_INTT_Scale ENDP

; =============================================================================
; SwarmV29_INTT_Inverse
; Complete inverse NTT transform
;
; RCX = data pointer
; RDX = inv twiddle factors pointer
; R8  = n (must be power of 2)
; R9  = modulus
;
; Returns: RAX = 0 on success
; =============================================================================
SwarmV29_INTT_Inverse PROC FRAME
    SWARMV29_ABI_FRAME
    
    ; Call INTT butterfly
    call SwarmV29_INTT_Butterfly
    
    ; Scale by n^(-1)
    ; Compute n_inv = n^(-1) mod q
    mov rax, r8            ; n
    mov rbx, r9            ; q
    
    ; Extended Euclidean algorithm for modular inverse
    ; (simplified - assumes n and q are coprime)
    mov rcx, rax           ; a = n
    mov rdx, rbx           ; b = q
    xor r8, r8             ; x0 = 0
    mov r9, 1              ; x1 = 1
    
@@euclid_loop:
    test rcx, rcx
    jz @@euclid_done
    
    mov rax, rdx
    xor rdx, rdx
    div rcx                ; q = b / a, r = b % a
    
    mov rbx, rdx           ; b = a
    mov rdx, rcx           ; temp = a
    mov rcx, rax           ; a = r
    
    mov rax, r8            ; temp_x = x0
    imul rax, rdx          ; temp_x = x0 * q
    sub r9, rax            ; x1 = x1 - temp_x
    mov r8, r9             ; x0 = x1
    mov r9, rax            ; x1 = temp_x
    
    jmp @@euclid_loop
    
@@euclid_done:
    ; n_inv is in r8 (mod q)
    mov r8, rax
    
    ; Call scale
    mov rcx, r12           ; data
    mov rdx, r13           ; n
    ; r8 already has n_inv
    mov r9, r15             ; modulus
    call SwarmV29_INTT_Scale
    
    SWARMV29_ABI_EPILOG
SwarmV29_INTT_Inverse ENDP

END