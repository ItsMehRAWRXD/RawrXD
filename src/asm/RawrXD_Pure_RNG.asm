; ============================================================================
; RawrXD_Pure_RNG.asm ? Deterministic PRNG for Pure MASM64 (No External Dependencies)
; Uses xorshift128+ algorithm ? fast, high-quality, zero dependencies
; ============================================================================
; Exports:
;   RawrXD_RNG_Seed      ? Initialize with 64-bit seed
;   RawrXD_RNG_Next64   ? Get next 64-bit random value
;   RawrXD_RNG_Next32   ? Get next 32-bit random value
;   RawrXD_RNG_NextFloat? Get random float in [0, 1)
;   RawrXD_RNG_Range    ? Get random value in [min, max]
; ============================================================================

OPTION CASEMAP:NONE

.data
ALIGN 16
rng_state0     DQ 0x853c49e6748fea9bULL    ; State word 0
rng_state1     DQ 0xda3e39cb94b95bdbULL    ; State word 1
rng_initialized DB 0

.code

; ----------------------------------------------------------------------------
; RawrXD_RNG_Seed ? Initialize PRNG state from 64-bit seed
; RCX = seed value (can be from RDTSC, process ID, etc.)
; ----------------------------------------------------------------------------
PUBLIC RawrXD_RNG_Seed
RawrXD_RNG_Seed PROC FRAME
    push    rbx
    .pushreg rbx
    sub     rsp, 32
    .allocstack 32
    .endprolog

    ; Initialize state using splitmix64 algorithm
    mov     rbx, rcx                    ; Save seed

    ; state0 = splitmix64(seed)
    mov     rax, rbx
    imul    rax, 0xBF58476D1CE4E5B9ULL
    mov     rdx, rax
    shr     rdx, 30
    add     rax, rdx
    imul    rax, 0xBF58476D1CE4E5B9ULL
    mov     rdx, rax
    shr     rdx, 30
    add     rax, rdx
    imul    rax, 0xBF58476D1CE4E5B9ULL
    mov     [rng_state0], rax

    ; state1 = splitmix64(seed + 0x9e3779b97f4a7c15)
    lea     rax, [rbx + 0x9e3779b97f4a7c15ULL]
    imul    rax, 0xBF58476D1CE4E5B9ULL
    mov     rdx, rax
    shr     rdx, 30
    add     rax, rdx
    imul    rax, 0xBF58476D1CE4E5B9ULL
    mov     rdx, rax
    shr     rdx, 30
    add     rax, rdx
    imul    rax, 0xBF58476D1CE4E5B9ULL
    mov     [rng_state1], rax

    ; Ensure non-zero state
    test    rax, rax
    jnz     @seed_done
    mov     [rng_state1], 0x6a09e667f3bcc909ULL

@seed_done:
    mov     byte ptr [rng_initialized], 1

    add     rsp, 32
    pop     rbx
    ret
RawrXD_RNG_Seed ENDP

; ----------------------------------------------------------------------------
; RawrXD_RNG_Next64 ? xorshift128+ algorithm
; Returns: RAX = 64-bit random value
; ----------------------------------------------------------------------------
PUBLIC RawrXD_RNG_Next64
RawrXD_RNG_Next64 PROC FRAME
    push    rbx
    .pushreg rbx
    sub     rsp, 24
    .allocstack 24
    .endprolog

    ; Load state
    mov     rax, [rng_state0]
    mov     rbx, [rng_state1]

    ; xorshift128+ core
    mov     rdx, rax                    ; s0 = state[0]
    mov     rcx, rbx                    ; s1 = state[1]
    
    ; state[0] = s1
    mov     [rng_state0], rcx
    
    ; s0 ^= s0 << 23
    mov     rax, rdx
    shl     rax, 23
    xor     rdx, rax
    
    ; state[1] = s0 ^ s1 ^ (s0 >> 17) ^ (s1 >> 26)
    mov     rax, rdx
    shr     rax, 17
    xor     rcx, rax
    mov     rax, rbx
    shr     rax, 26
    xor     rcx, rax
    xor     rcx, rdx
    mov     [rng_state1], rcx
    
    ; result = state[0] + state[1]
    mov     rax, [rng_state0]
    add     rax, rcx

    add     rsp, 24
    pop     rbx
    ret
RawrXD_RNG_Next64 ENDP

; ----------------------------------------------------------------------------
; RawrXD_RNG_Next32 ? Get 32-bit random value
; Returns: EAX = 32-bit random value
; ----------------------------------------------------------------------------
PUBLIC RawrXD_RNG_Next32
RawrXD_RNG_Next32 PROC FRAME
    sub     rsp, 32
    .allocstack 32
    .endprolog

    call    RawrXD_RNG_Next64
    mov     eax, eax                    ; Zero-extend to 32-bit

    add     rsp, 32
    ret
RawrXD_RNG_Next32 ENDP

; ----------------------------------------------------------------------------
; RawrXD_RNG_NextFloat ? Get random float in [0, 1)
; Returns: XMM0 = float in [0, 1)
; ----------------------------------------------------------------------------
PUBLIC RawrXD_RNG_NextFloat
RawrXD_RNG_NextFloat PROC FRAME
    sub     rsp, 40
    .allocstack 40
    .endprolog

    call    RawrXD_RNG_Next64
    
    ; Convert to float: take upper 53 bits for mantissa
    ; float = (random >> 11) * (1.0 / (1 << 53))
    shr     rax, 11                     ; Keep 53 bits
    cvtsi2sd xmm0, rax                  ; Convert to double
    
    ; Multiply by 1/(2^53) = 1.1102230246251565e-16
    movsd   xmm1, 1.1102230246251565e-16
    mulsd   xmm0, xmm1
    
    ; Convert to single precision
    cvtsd2ss xmm0, xmm0

    add     rsp, 40
    ret
RawrXD_RNG_NextFloat ENDP

; ----------------------------------------------------------------------------
; RawrXD_RNG_Range ? Get random value in [min, max]
; RCX = min, RDX = max
; Returns: RAX = random value in [min, max]
; ----------------------------------------------------------------------------
PUBLIC RawrXD_RNG_Range
RawrXD_RNG_Range PROC FRAME
    push    rbx
    .pushreg rbx
    push    rsi
    .pushreg rsi
    sub     rsp, 32
    .allocstack 32
    .endprolog

    mov     rbx, rcx                    ; min
    mov     rsi, rdx                    ; max
    
    ; Compute range: range = max - min + 1
    sub     rsi, rbx
    inc     rsi
    
    ; Get random value
    call    RawrXD_RNG_Next64
    
    ; result = min + (random % range)
    xor     rdx, rdx
    div     rsi                         ; RAX = random % range
    add     rax, rbx                    ; result = min + (random % range)

    add     rsp, 32
    pop     rsi
    pop     rbx
    ret
RawrXD_RNG_Range ENDP

; ----------------------------------------------------------------------------
; RawrXD_RNG_InitFromEntropy ? Initialize from system entropy (RDTSC + process info)
; No parameters, uses RDTSC and GetCurrentProcessId
; ----------------------------------------------------------------------------
EXTERN GetCurrentProcessId:PROC
EXTERN GetTickCount64:PROC

PUBLIC RawrXD_RNG_InitFromEntropy
RawrXD_RNG_InitFromEntropy PROC FRAME
    push    rbx
    .pushreg rbx
    sub     rsp, 32
    .allocstack 32
    .endprolog

    ; Gather entropy from multiple sources
    rdtsc                               ; EDX:EAX = timestamp
    shl     rdx, 32
    or      rax, rdx
    mov     rbx, rax                    ; Save RDTSC
    
    ; XOR with process ID
    call    GetCurrentProcessId
    xor     rbx, rax
    
    ; XOR with tick count
    call    GetTickCount64
    xor     rbx, rax
    
    ; XOR with stack address (ASLR entropy)
    lea     rax, [rsp]
    xor     rbx, rax
    
    ; XOR with code address (ASLR entropy)
    lea     rax, @entropy_ret
    xor     rbx, rax
    
    ; Initialize with combined entropy
    mov     rcx, rbx
    call    RawrXD_RNG_Seed

@entropy_ret:
    add     rsp, 32
    pop     rbx
    ret
RawrXD_RNG_InitFromEntropy ENDP

END
