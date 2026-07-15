; ============================================================================
; RawrXD Immutable Execution Fabric - Hash Kernel
; Phase 7C: Deterministic Hashing Primitive
; ============================================================================
; Pure x64 MASM implementation of xxHash-style hashing
; No dependencies, no CRT, no external libraries
; ============================================================================

; xxHash constants (in hex for MASM compatibility)
XXH_PRIME64_1 EQU 09E3779B185EBCA87h
XXH_PRIME64_2 EQU 0C2B2AE3D27D4EB4Fh
XXH_PRIME64_3 EQU 0165667B19E3779F9h
XXH_PRIME64_4 EQU 085EBCA77C2B2AE63h
XXH_PRIME64_5 EQU 027D4EB2F165667C5h

; FNV constants
FNV_OFFSET EQU 014695729503346656037
FNV_PRIME  EQU 01099511628211

; ============================================================================
; DATA SECTION
; ============================================================================
.data
    align 8

; ============================================================================
; CODE SECTION
; ============================================================================
.code

; ============================================================================
; RawrXD_Hash64 - Fast 64-bit hash of memory region
; 
; Arguments:
;   RCX = data pointer (const void*)
;   RDX = size in bytes (size_t)
;   R8  = seed (uint64_t)
;
; Returns:
;   RAX = 64-bit hash value
; ============================================================================
RawrXD_Hash64 PROC FRAME
    ; Save non-volatile registers (minimize for prolog < 256 bytes)
    push rbx
    .pushreg rbx
    push rdi
    .pushreg rdi
    push rsi
    .pushreg rsi
    push r12
    .pushreg r12
    push r13
    .pushreg r13
    push r14
    .pushreg r14
    .endprolog

    ; Check for empty input
    test rdx, rdx
    jz hash_empty

    ; Initialize state with seed
    mov r12, rcx        ; r12 = data pointer
    mov r13, rdx        ; r13 = remaining length
    mov r14, r8         ; r14 = seed

    ; Check if we have at least 32 bytes for striped processing
    cmp r13, 32
    jb hash_small

    ; Initialize 4 accumulators for striped processing
    mov rax, XXH_PRIME64_1
    add rax, r14        ; acc1 = seed + PRIME64_1
    mov rbx, rax        ; rbx = acc1
    add rbx, XXH_PRIME64_2  ; acc2 = acc1 + PRIME64_2
    mov rdi, rax        ; rdi = acc1
    add rdi, XXH_PRIME64_3  ; acc3 = acc1 + PRIME64_3
    mov rsi, rax        ; rsi = acc1
    add rsi, XXH_PRIME64_4  ; acc4 = acc1 + PRIME64_4
    mov r14, rax        ; r14 = acc1 (original acc1)

striped_loop:
    cmp r13, 32
    jb striped_done

    ; Process 32 bytes (4 x 8 bytes)
    ; Load and process first 8 bytes
    mov rax, [r12]
    mov r15, XXH_PRIME64_2
    mul r15             ; rax = data * PRIME64_2
    add r14, rax        ; acc1 += result
    rol r14, 31
    mov rax, XXH_PRIME64_1
    mul r14             ; acc1 *= PRIME64_1
    mov r14, rax
    
    ; Second 8 bytes
    mov rax, [r12 + 8]
    mul r15
    add rbx, rax
    rol rbx, 31
    mov rax, XXH_PRIME64_1
    mul rbx
    mov rbx, rax
    
    ; Third 8 bytes
    mov rax, [r12 + 16]
    mul r15
    add rdi, rax
    rol rdi, 31
    mov rax, XXH_PRIME64_1
    mul rdi
    mov rdi, rax
    
    ; Fourth 8 bytes
    mov rax, [r12 + 24]
    mul r15
    add rsi, rax
    rol rsi, 31
    mov rax, XXH_PRIME64_1
    mul rsi
    mov rsi, rax

    add r12, 32
    sub r13, 32
    jmp striped_loop

striped_done:
    ; Merge accumulators
    mov rax, rbx
    rol rax, 1
    add rdi, rax        ; acc3 += acc2 rotated left 1
    
    mov rax, rsi
    rol rax, 7
    add rbx, rax        ; acc2 += acc4 rotated left 7
    
    mov rax, rdi
    rol rax, 12
    add rsi, rax        ; acc4 += acc3 rotated left 12
    
    mov rax, rbx
    rol rax, 18
    add r14, rax        ; acc1 += acc2 rotated left 18
    
    ; Final merge
    mov rax, r14
    mov r15, XXH_PRIME64_1
    mul r15
    add rax, rdi
    mul r15
    add rax, rbx
    mul r15
    add rax, rsi
    mul r15
    jmp process_remainder

hash_small:
    ; For small inputs (< 32 bytes), use simple accumulator
    mov rax, r14
    add rax, XXH_PRIME64_5
    add rax, r13        ; acc = seed + PRIME64_5 + len

process_remainder:
    ; Process remaining bytes (0-31)
    cmp r13, 8
    jb check_4_bytes
    
    ; Process 8 bytes at a time
remainder_8_loop:
    cmp r13, 8
    jb check_4_bytes
    
    mov r15, [r12]
    ; round64: rax = accumulator, r15 = data
    mov rcx, XXH_PRIME64_2
    mov r8, r15
    mul rcx             ; r15 * PRIME64_2
    mov r15, r8
    imul r15, XXH_PRIME64_2
    add rax, r15
    rol rax, 27
    mov r15, XXH_PRIME64_1
    mul r15
    mov r15, XXH_PRIME64_4
    mul r15
    
    add r12, 8
    sub r13, 8
    jmp remainder_8_loop

check_4_bytes:
    cmp r13, 4
    jb check_2_bytes
    
    movzx r15, dword ptr [r12]
    mov rcx, XXH_PRIME64_1
    mov rax, r15
    mul rcx
    add rax, r15
    rol rax, 23
    mov rcx, XXH_PRIME64_2
    mul rcx
    add r12, 4
    sub r13, 4

check_2_bytes:
    cmp r13, 2
    jb check_1_byte
    
    movzx r15, word ptr [r12]
    mov rcx, XXH_PRIME64_5
    mov rax, r15
    mul rcx
    add rax, r15
    rol rax, 11
    mov rcx, XXH_PRIME64_1
    mul rcx
    add r12, 2
    sub r13, 2

check_1_byte:
    cmp r13, 1
    jb finalize
    
    movzx r15, byte ptr [r12]
    mov rcx, XXH_PRIME64_5
    mov rax, r15
    mul rcx
    add rax, r15
    rol rax, 11
    mov rcx, XXH_PRIME64_1
    mul rcx

finalize:
    ; Final avalanche
    mov r15, rax
    shr r15, 33
    xor rax, r15
    mov rcx, XXH_PRIME64_2
    mul rcx
    
    mov r15, rax
    shr r15, 29
    xor rax, r15
    mov rcx, XXH_PRIME64_3
    mul rcx
    
    mov r15, rax
    shr r15, 32
    xor rax, r15
    
    jmp hash_done

hash_empty:
    ; Return hash of empty string
    mov rax, XXH_PRIME64_5

hash_done:
    ; Restore registers and return
    pop r14
    pop r13
    pop r12
    pop rsi
    pop rdi
    pop rbx
    ret
RawrXD_Hash64 ENDP

; ============================================================================
; RawrXD_Hash64_Simple - Simple but fast 64-bit hash (fallback)
; ============================================================================
RawrXD_Hash64_Simple PROC FRAME
    push rbx
    .pushreg rbx
    push rdi
    .pushreg rdi
    .endprolog

    mov rdi, rcx        ; rdi = data
    mov rcx, rdx        ; rcx = size
    mov rbx, r8         ; rbx = seed
    
    ; Simple FNV-1a style hash
    mov rax, 0cbf29ce484222325h  ; FNV offset basis
    xor rax, rbx        ; Mix in seed
    
    test rcx, rcx
    jz simple_done

simple_loop:
    movzx rdx, byte ptr [rdi]
    xor rax, rdx
    mov r8, 100000001b3h      ; FNV prime
    mul r8
    inc rdi
    dec rcx
    jnz simple_loop

simple_done:
    ; Final mix
    mov rdx, rax
    shr rdx, 33
    xor rax, rdx
    mov r8, 0ff51afd7ed558ccdh
    mul r8
    mov rdx, rax
    shr rdx, 33
    xor rax, rdx
    mov r8, 0c4ceb9fe1a85ec53h
    mul r8
    mov rdx, rax
    shr rdx, 33
    xor rax, rdx

    pop rdi
    pop rbx
    ret
RawrXD_Hash64_Simple ENDP

; ============================================================================
; RawrXD_HashCombine - Combine two hash values
; ============================================================================
RawrXD_HashCombine PROC FRAME
    .endprolog
    
    ; Boost::hash_combine style
    mov rax, rcx
    xor rax, rdx
    mov r8, XXH_PRIME64_1
    mul r8
    rol rax, 17
    mov r8, XXH_PRIME64_2
    mul r8
    
    ret
RawrXD_HashCombine ENDP

; ============================================================================
; RawrXD_HashFloat32 - Deterministic hash of float array
; ============================================================================
RawrXD_HashFloat32 PROC FRAME
    push rbx
    .pushreg rbx
    push rdi
    .pushreg rdi
    push r12
    .pushreg r12
    push r13
    .pushreg r13
    push r14
    .pushreg r14
    .endprolog

    mov rdi, rcx        ; rdi = float array
    mov r12, rdx        ; r12 = count
    mov r13, r8         ; r13 = seed
    
    ; Initialize hash state
    mov r14, XXH_PRIME64_5
    add r14, r13
    add r14, r12        ; seed + PRIME64_5 + count

float_loop:
    test r12, r12
    jz float_done
    
    ; Load float and normalize
    mov eax, [rdi]
    
    ; Check for negative zero
    cmp eax, 080000000h
    jne check_nan
    xor eax, eax        ; Convert -0.0 to +0.0
    
check_nan:
    ; Check if NaN (exponent all 1s, mantissa non-zero)
    mov ebx, eax
    and ebx, 07F800000h
    cmp ebx, 07F800000h
    jne not_nan
    
    ; It's either Inf or NaN
    test eax, 007FFFFFh
    jz not_nan          ; It's Inf, keep as-is
    
    ; It's NaN, use canonical form
    mov eax, 07FC00000h
    
not_nan:
    ; Hash the normalized float bits (byte by byte)
    movzx rbx, al
    mov rcx, XXH_PRIME64_5
    mov rax, rbx
    mul rcx
    add r14, rax
    rol r14, 11
    mov rcx, XXH_PRIME64_1
    mov rax, r14
    mul rcx
    mov r14, rax
    
    shr eax, 8
    movzx rbx, al
    mov rcx, XXH_PRIME64_5
    mov rax, rbx
    mul rcx
    add r14, rax
    rol r14, 11
    mov rcx, XXH_PRIME64_1
    mov rax, r14
    mul rcx
    mov r14, rax
    
    shr eax, 8
    movzx rbx, al
    mov rcx, XXH_PRIME64_5
    mov rax, rbx
    mul rcx
    add r14, rax
    rol r14, 11
    mov rcx, XXH_PRIME64_1
    mov rax, r14
    mul rcx
    mov r14, rax
    
    shr eax, 8
    movzx rbx, al
    mov rcx, XXH_PRIME64_5
    mov rax, rbx
    mul rcx
    add r14, rax
    rol r14, 11
    mov rcx, XXH_PRIME64_1
    mov rax, r14
    mul rcx
    mov r14, rax
    
    add rdi, 4
    dec r12
    jmp float_loop

float_done:
    ; Final avalanche
    mov rax, r14
    mov rbx, rax
    shr rbx, 33
    xor rax, rbx
    mov rcx, XXH_PRIME64_2
    mul rcx
    
    mov rbx, rax
    shr rbx, 29
    xor rax, rbx
    mov rcx, XXH_PRIME64_3
    mul rcx
    
    mov rbx, rax
    shr rbx, 32
    xor rax, rbx

    pop r14
    pop r13
    pop r12
    pop rdi
    pop rbx
    ret
RawrXD_HashFloat32 ENDP

END
