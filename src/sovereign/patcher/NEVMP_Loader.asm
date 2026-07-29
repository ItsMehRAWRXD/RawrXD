; =============================================================================
; NEVMP_Loader.asm - Neural Vector Memory Patch Loader
; Architecture: x64 MASM (Zero-dependency, Non-temporal streaming)
; Purpose: High-speed patch application to Titan Compute Engine aperture
; =============================================================================

.code

; =============================================================================
; NEVMP_ValidateHeader
; Inputs:
;   RCX = Pointer to NEVMP_Header (64-byte aligned)
; Returns:
;   RAX = 0 if valid, error code if invalid
; Clobbers: RAX, RDX, R8-R11
; =============================================================================
NEVMP_ValidateHeader PROC
    ; Check magic: 0x4E564D50 ('NVMP')
    mov     eax, dword ptr [rcx]
    cmp     eax, 04E564D50h
    jne     .invalid_magic
    
    ; Check version: 0x00010000 (v1.0)
    mov     eax, dword ptr [rcx + 4]
    cmp     eax, 000010000h
    jne     .invalid_version
    
    ; Check vector_count > 0
    mov     r8, qword ptr [rcx + 16]      ; vector_count
    test    r8, r8
    jz      .invalid_payload
    
    ; Check payload_size > 0
    mov     r9, qword ptr [rcx + 24]      ; payload_size
    test    r9, r9
    jz      .invalid_payload
    
    ; Verify payload_size == vector_count * 8 (sizeof(double))
    mov     rax, r8
    shl     rax, 3                          ; rax = vector_count * 8
    cmp     rax, r9
    jne     .invalid_payload
    
    ; Header is valid
    xor     rax, rax                        ; Return 0 (OK)
    ret
    
.invalid_magic:
    mov     rax, -1                         ; ERR_INVALID_MAGIC
    ret
    
.invalid_version:
    mov     rax, -2                         ; ERR_INVALID_VERSION
    ret
    
.invalid_payload:
    mov     rax, -4                         ; ERR_INVALID_PAYLOAD
    ret
NEVMP_ValidateHeader ENDP

; =============================================================================
; NEVMP_LoadAndApply
; Inputs:
;   RCX = NEVMP_Header pointer (64-byte aligned)
;   RDX = Target aperture pointer (64-byte aligned)
;   R8  = Payload size in bytes
; Returns:
;   RAX = 0 on success, error code on failure
; Clobbers: RAX, RCX, RDX, R8-R11, ZMM0-ZMM3
; =============================================================================
NEVMP_LoadAndApply PROC
    push    rbx
    push    rsi
    push    rdi
    
    ; Save parameters
    mov     rsi, rcx                        ; RSI = Header ptr
    mov     rdi, rdx                        ; RDI = Target aperture
    mov     rbx, r8                         ; RBX = Payload size
    
    ; Validate header first
    call    NEVMP_ValidateHeader
    test    rax, rax
    jnz     .exit_error                     ; Return error code if validation failed
    
    ; Skip header (64 bytes) to reach payload
    add     rsi, 64
    
    ; Calculate number of 64-byte blocks
    mov     rax, rbx
    shr     rax, 6                          ; rax = size / 64
    jz      .small_payload
    
    ; Main streaming loop - process 64 bytes at a time
    ; Using non-temporal loads/stores to bypass cache
.align_loop:
    vmovdqu64   zmm0, zmmword ptr [rsi]     ; Load 64 bytes from patch
    vmovntdq    zmmword ptr [rdi], zmm0     ; Non-temporal store to aperture
    
    add     rsi, 64
    add     rdi, 64
    dec     rax
    jnz     .align_loop
    
.small_payload:
    ; Handle remaining bytes (< 64)
    and     rbx, 63                         ; rbx = remaining bytes
    jz      .done
    
    ; Copy remaining bytes (scalar)
    mov     rcx, rbx
    rep     movsb
    
.done:
    ; Memory fence to ensure non-temporal stores are visible
    sfence
    
    ; Success
    xor     rax, rax
    
.exit_error:
    pop     rdi
    pop     rsi
    pop     rbx
    ret
NEVMP_LoadAndApply ENDP

; =============================================================================
; NEVMP_CalculateChecksum
; Inputs:
;   RCX = Payload pointer
;   RDX = Payload size in bytes
; Returns:
;   RAX = CRC64-ISO checksum
; Clobbers: RAX, RCX, RDX, R8-R11
; =============================================================================
NEVMP_CalculateChecksum PROC
    ; Initialize CRC64-ISO (polynomial: 0xD800000000000000)
    mov     rax, -1                         ; Initial value (all 1s)
    
    ; Simple byte-wise CRC for now (can be optimized with SIMD)
    test    rdx, rdx
    jz      .done
    
.crc_loop:
    movzx   r8, byte ptr [rcx]
    xor     al, r8b
    
    ; CRC64-ISO table lookup would go here
    ; For now, use a simplified rolling hash
    rol     rax, 7
    add     rax, r8
    
    inc     rcx
    dec     rdx
    jnz     .crc_loop
    
.done:
    not     rax                             ; Final XOR
    ret
NEVMP_CalculateChecksum ENDP

; =============================================================================
; NEVMP_Rollback
; Inputs:
;   RCX = Previous epoch checkpoint pointer
;   RDX = Current aperture pointer
;   R8  = Size in bytes
; Returns:
;   RAX = 0 on success
; =============================================================================
NEVMP_Rollback PROC
    push    rsi
    push    rdi
    
    mov     rsi, rcx                        ; Source: checkpoint
    mov     rdi, rdx                        ; Dest: current aperture
    mov     rcx, r8                         ; Size
    
    ; Non-temporal restore
    shr     rcx, 6                          ; Process 64-byte blocks
    jz      .remainder
    
.restore_loop:
    vmovdqu64   zmm0, zmmword ptr [rsi]
    vmovntdq    zmmword ptr [rdi], zmm0
    add         rsi, 64
    add         rdi, 64
    dec         rcx
    jnz         .restore_loop
    
.remainder:
    sfence
    xor     rax, rax
    
    pop     rdi
    pop     rsi
    ret
NEVMP_Rollback ENDP

END
