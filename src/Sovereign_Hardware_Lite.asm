; ==============================================================================
; Sovereign_Hardware_Lite.asm — Self-contained hardware audit + pattern scanner
; Provides Sovereign_Hardware_Audit and Sovereign_ScanPattern with zero deps.
; ==============================================================================

include Sovereign_Common.inc

.DATA
PUBLIC g_CpuFlags
g_CpuFlags dq 0          ; bit0 = AVX2, bit1 = AVX-512F, bit2 = AES-NI

.CODE

; ------------------------------------------------------------------------------
; Sovereign_Hardware_Audit — CPUID feature detection, sets g_CpuFlags
; Clobbers RAX, RBX, RCX, RDX
; ------------------------------------------------------------------------------
PUBLIC Sovereign_Hardware_Audit
Sovereign_Hardware_Audit PROC
    push rbx
    xor r10, r10

    ; Leaf 1 -> ECX bit 25 = AES-NI
    mov eax, 1
    xor ecx, ecx
    cpuid
    test ecx, 002000000h
    jz @@no_aes
    or r10, 4
@@no_aes:

    ; Leaf 7 -> EBX bit 5 = AVX2, bit 16 = AVX-512F
    mov eax, 7
    xor ecx, ecx
    cpuid
    test ebx, 020h
    jz @@no_avx2
    or r10, 1
@@no_avx2:
    test ebx, 010000h
    jz @@no_avx512
    or r10, 2
@@no_avx512:

    mov [g_CpuFlags], r10
    mov rax, r10
    pop rbx
    ret
Sovereign_Hardware_Audit ENDP

; ------------------------------------------------------------------------------
; Sovereign_ScanPattern
; RCX = base, RDX = size_bytes, R8 = pattern_ptr, R9 = pattern_len (1..8)
; Returns RAX = pointer to first occurrence or 0
; Pure SSE2 byte-wise scan; deterministic and CPU-feature agnostic.
; ------------------------------------------------------------------------------
PUBLIC Sovereign_ScanPattern
Sovereign_ScanPattern PROC
    push rdi
    push rsi
    push rbx
    test rcx, rcx
    jz @@miss
    test rdx, rdx
    jz @@miss
    test r9, r9
    jz @@miss
    cmp r9, rdx
    ja  @@miss

    ; First byte of the pattern broadcast to all bytes of XMM1
    movzx eax, byte ptr [r8]
    movd  xmm1, eax
    punpcklbw xmm1, xmm1
    punpcklwd xmm1, xmm1
    pshufd   xmm1, xmm1, 0

    mov r10, rcx                ; cursor
    mov r11, rdx                ; remaining
    sub r11, r9                 ; last valid start

@@outer:
    cmp r11, 16
    jb  @@scalar
    movdqu xmm0, xmmword ptr [r10]
    pcmpeqb xmm0, xmm1
    pmovmskb eax, xmm0
    test eax, eax
    jz  @@advance16

@@bit_loop:
    bsf ecx, eax
    lea rdi, [r10 + rcx]
    mov rsi, r8
    mov rbx, r9
@@verify:
    mov dl, [rsi]
    cmp dl, [rdi]
    jne @@verify_fail
    inc rsi
    inc rdi
    dec rbx
    jnz @@verify
    lea rax, [r10 + rcx]
    jmp @@found
@@verify_fail:
    btr eax, ecx
    test eax, eax
    jnz @@bit_loop

@@advance16:
    add r10, 16
    sub r11, 16
    jmp @@outer

@@scalar:
    test r11, r11
    js  @@miss
@@scalar_loop:
    mov al, [r10]
    cmp al, byte ptr [r8]
    jne @@scalar_next
    mov rsi, r8
    mov rdi, r10
    mov rbx, r9
@@sv:
    mov dl, [rsi]
    cmp dl, [rdi]
    jne @@scalar_next
    inc rsi
    inc rdi
    dec rbx
    jnz @@sv
    mov rax, r10
    jmp @@found
@@scalar_next:
    inc r10
    dec r11
    jns @@scalar_loop

@@miss:
    xor rax, rax
@@found:
    pop rbx
    pop rsi
    pop rdi
    ret
Sovereign_ScanPattern ENDP

END
