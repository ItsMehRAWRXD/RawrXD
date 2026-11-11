; =============================================================================
; Puppeteer_CaptureState.asm - Runtime State Capture for Self-Modification
; Architecture: x64 MASM (Zero-dependency)
; Purpose: Capture full CPU state before/after self-modification
; =============================================================================

.code

; =============================================================================
; Puppeteer_CaptureState
; Inputs:
;   RCX = Pointer to MemorySnapshot structure
; Returns:
;   None (fills the structure)
; Clobbers: RAX, RDX, R8-R11, XMM0-XMM3 (intentional)
; =============================================================================
Puppeteer_CaptureState PROC
    push    rbp
    mov     rbp, rsp
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    push    r15
    
    ; RCX = destination MemorySnapshot
    mov     rdi, rcx
    
    ; -------------------------------------------------------------------------
    ; Capture General Purpose Registers
    ; -------------------------------------------------------------------------
    mov     [rdi + 0], rax          ; RIP (will be filled from return address)
    mov     [rdi + 8], rsp
    mov     [rdi + 16], rbp
    
    mov     [rdi + 24], rax
    mov     [rdi + 32], rbx
    mov     [rdi + 40], rcx
    mov     [rdi + 48], rdx
    mov     [rdi + 56], rsi
    mov     [rdi + 64], rdi
    mov     [rdi + 72], r8
    mov     [rdi + 80], r9
    mov     [rdi + 88], r10
    mov     [rdi + 96], r11
    mov     [rdi + 104], r12
    mov     [rdi + 112], r13
    mov     [rdi + 120], r14
    mov     [rdi + 128], r15
    
    ; -------------------------------------------------------------------------
    ; Capture EFLAGS
    ; -------------------------------------------------------------------------
    pushfq
    pop     rax
    mov     [rdi + 136], eax        ; EFLAGS (32-bit)
    
    ; -------------------------------------------------------------------------
    ; Capture MXCSR (SSE Control/Status)
    ; -------------------------------------------------------------------------
    stmxcsr [rdi + 140]             ; MXCSR at offset 140
    
    ; -------------------------------------------------------------------------
    ; Capture RIP from return address
    ; -------------------------------------------------------------------------
    mov     rax, [rbp + 8]          ; Return address
    mov     [rdi + 0], rax          ; Store as RIP
    
    ; -------------------------------------------------------------------------
    ; Capture Vector State (AVX-512)
    ; -------------------------------------------------------------------------
    ; Save ZMM0-ZMM3 to vector_state buffer (offset 144)
    vmovdqu64 zmmword ptr [rdi + 144 + 0*64], zmm0
    vmovdqu64 zmmword ptr [rdi + 144 + 1*64], zmm1
    vmovdqu64 zmmword ptr [rdi + 144 + 2*64], zmm2
    vmovdqu64 zmmword ptr [rdi + 144 + 3*64], zmm3
    
    ; -------------------------------------------------------------------------
    ; Calculate Region Hash (simple checksum of code region)
    ; -------------------------------------------------------------------------
    ; Hash = sum of bytes in 256 bytes following RIP
    mov     rsi, [rdi + 0]          ; RIP
    xor     rdx, rdx                ; Hash accumulator
    mov     rcx, 256                ; Bytes to hash
    
hash_loop:
    movzx   rax, byte ptr [rsi]
    add     rdx, rax
    rol     rdx, 7
    inc     rsi
    dec     rcx
    jnz     hash_loop
    
    mov     [rdi + 656], rdx        ; Store region_hash
    
    ; Restore and return
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    pop     rbp
    ret
Puppeteer_CaptureState ENDP

; =============================================================================
; Puppeteer_ValidateCode
; Inputs:
;   RCX = Code address to validate
;   RDX = Size of code region
; Returns:
;   RAX = 1 if valid, 0 if invalid
; =============================================================================
Puppeteer_ValidateCode PROC
    push    rbp
    mov     rbp, rsp
    push    rsi
    push    rdi
    
    mov     rsi, rcx                ; RSI = code address
    mov     rdi, rdx                ; RDI = size
    
    ; Check for invalid opcodes
    mov     rcx, rdi
    jrcxz   valid                  ; Empty region is valid
    
check_loop:
    movzx   eax, byte ptr [rsi]
    
    ; Check for privileged instructions
    cmp     al, 0Fh                 ; Two-byte opcode prefix
    jne     next_byte
    
    ; Check second byte
    movzx   eax, byte ptr [rsi + 1]
    
    ; WRMSR (0F 30) - privileged
    cmp     al, 30h
    je      invalid
    
    ; RDMSR (0F 32) - privileged
    cmp     al, 32h
    je      invalid
    
    ; LGDT (0F 01 /2) - privileged
    cmp     al, 01h
    je      invalid
    
    ; LIDT (0F 01 /3) - privileged
    cmp     al, 01h
    je      invalid
    
next_byte:
    inc     rsi
    dec     rcx
    jnz     check_loop
    
valid:
    mov     rax, 1
    jmp     exit_label
    
invalid:
    xor     rax, rax
    
exit_label:
    pop     rdi
    pop     rsi
    pop     rbp
    ret
Puppeteer_ValidateCode ENDP

; =============================================================================
; Puppeteer_CompareStates
; Inputs:
;   RCX = Pointer to state A
;   RDX = Pointer to state B
; Returns:
;   RAX = 1 if equal, 0 if different
; =============================================================================
Puppeteer_CompareStates PROC
    push    rbp
    mov     rbp, rsp
    push    rsi
    push    rdi
    push    rbx
    
    mov     rsi, rcx                ; RSI = state A
    mov     rdi, rdx                ; RDI = state B
    
    ; Compare GPRs (136 bytes)
    mov     rcx, 136
    repe    cmpsb
    jne     different
    
    ; Compare vector state (512 bytes)
    mov     rcx, 512
    repe    cmpsb
    jne     different
    
    ; Compare region hash (8 bytes)
    mov     rax, [rsi]
    cmp     rax, [rdi]
    jne     different
    
equal:
    mov     rax, 1
    jmp     exit_label2
    
different:
    xor     rax, rax
    
exit_label2:
    pop     rbx
    pop     rdi
    pop     rsi
    pop     rbp
    ret
Puppeteer_CompareStates ENDP

END
