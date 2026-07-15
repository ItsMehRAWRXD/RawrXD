; ============================================================================
; RawrXD Immutable Execution Fabric - Hash Kernel (Simplified)
; Phase 7C: Deterministic Hashing Primitive
; ============================================================================
; Pure x64 MASM - simplified for compatibility
; ============================================================================

; ============================================================================
; CODE SECTION
; ============================================================================
.code

; ============================================================================
; RawrXD_Hash64 - Fast 64-bit hash using FNV-1a variant
; Arguments: RCX=data, RDX=len, R8=seed
; Returns: RAX=hash
; ============================================================================
RawrXD_Hash64 PROC
    ; Prolog - save registers
    push rbx
    push rdi
    push rsi
    push r12
    push r13
    
    mov rdi, rcx        ; rdi = data pointer
    mov rbx, rdx        ; rbx = length
    mov rax, r8         ; rax = seed (start with seed)
    
    ; Initialize with FNV offset basis XOR seed
    mov r12, 0cbf29ce484222325h
    xor rax, r12
    
    test rbx, rbx
    jz hash_done
    
hash_loop:
    movzx r12, byte ptr [rdi]
    xor rax, r12
    
    ; Multiply by FNV prime (0x100000001b3)
    mov r12, rax
    shl rax, 1
    shl r12, 4
    add rax, r12
    shl r12, 1
    add rax, r12          ; rax = rax * 0x11 = rax * 17 (approximation)
    
    ; Better: use actual multiplication
    mov r12, 100000001b3h
    mul r12
    
    inc rdi
    dec rbx
    jnz hash_loop
    
    ; Final mix
    mov r12, rax
    shr r12, 33
    xor rax, r12
    mov r12, 0ff51afd7ed558ccdh
    mul r12
    mov r12, rax
    shr r12, 33
    xor rax, r12
    mov r12, 0c4ceb9fe1a85ec53h
    mul r12
    mov r12, rax
    shr r12, 33
    xor rax, r12
    
hash_done:
    pop r13
    pop r12
    pop rsi
    pop rdi
    pop rbx
    ret
RawrXD_Hash64 ENDP

; ============================================================================
; RawrXD_Hash64_Simple - Simple FNV-1a hash
; ============================================================================
RawrXD_Hash64_Simple PROC
    push rbx
    push rdi
    
    mov rdi, rcx
    mov rbx, rdx
    mov rax, 0cbf29ce484222325h
    xor rax, r8
    
    test rbx, rbx
    jz simple_done
    
simple_loop:
    movzx rdx, byte ptr [rdi]
    xor rax, rdx
    mov rcx, 100000001b3h
    mul rcx
    inc rdi
    dec rbx
    jnz simple_loop
    
simple_done:
    pop rdi
    pop rbx
    ret
RawrXD_Hash64_Simple ENDP

; ============================================================================
; RawrXD_HashCombine - Combine two hashes
; ============================================================================
RawrXD_HashCombine PROC
    mov rax, rcx
    xor rax, rdx
    mov rcx, 09e3779b97f4a7c15h
    mul rcx
    rol rax, 17
    mov rcx, 0c2b2ae3d27d4eb4fh
    mul rcx
    ret
RawrXD_HashCombine ENDP

; ============================================================================
; RawrXD_HashFloat32 - Hash float array with NaN normalization
; ============================================================================
RawrXD_HashFloat32 PROC
    push rbx
    push rdi
    push r12
    push r13
    push r14
    
    mov rdi, rcx        ; float array
    mov r12, rdx        ; count
    mov r13, r8         ; seed
    
    ; Initialize hash
    mov r14, 027d4eb2f165667c5h
    add r14, r13
    add r14, r12
    
float_loop:
    test r12, r12
    jz float_done
    
    mov eax, [rdi]
    
    ; Normalize -0.0
    cmp eax, 080000000h
    jne check_nan
    xor eax, eax
    
check_nan:
    ; Check for NaN
    mov ebx, eax
    and ebx, 07f800000h
    cmp ebx, 07f800000h
    jne hash_float
    test eax, 007fffffh
    jz hash_float
    mov eax, 07fc00000h   ; Canonical NaN
    
hash_float:
    ; Hash each byte
    movzx rbx, al
    add r14, rbx
    rol r14, 11
    mov rcx, 09e3779b97f4a7c15h
    mov rax, r14
    mul rcx
    mov r14, rax
    
    shr eax, 8
    movzx rbx, al
    add r14, rbx
    rol r14, 11
    mov rax, r14
    mul rcx
    mov r14, rax
    
    shr eax, 8
    movzx rbx, al
    add r14, rbx
    rol r14, 11
    mov rax, r14
    mul rcx
    mov r14, rax
    
    shr eax, 8
    movzx rbx, al
    add r14, rbx
    rol r14, 11
    mov rax, r14
    mul rcx
    mov r14, rax
    
    add rdi, 4
    dec r12
    jmp float_loop
    
float_done:
    ; Final mix
    mov rax, r14
    mov rbx, rax
    shr rbx, 33
    xor rax, rbx
    mov rcx, 0c2b2ae3d27d4eb4fh
    mul rcx
    mov rbx, rax
    shr rbx, 29
    xor rax, rbx
    mov rcx, 0165667b19e3779f9h
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
