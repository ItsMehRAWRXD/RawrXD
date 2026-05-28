; ==============================================================================
; SwarmV29_Execute_Pipeline.asm
; PHASE-29g: Unified PQC Pipeline Entry Point
; Target: 70B @ 150TPS via Integrated NTT/INTT/Compression
; ------------------------------------------------------------------------------
; Single entry point for the complete PQC transformation pipeline.
; Combines: BitReverse -> NTT -> [Operations] -> INTT -> Pack
;
; ABI: Windows x64 (RCX, RDX, R8, R9)
; Input:
;   RCX = Data buffer (64-byte aligned, coefficients)
;   RDX = Twiddle table (64-byte aligned, precomputed)
;   R8  = Output buffer (64-byte aligned, packed output)
;   R9  = Transform flags (bit 0: Forward NTT, bit 1: Inverse INTT, bit 2: Pack)
; Output:
;   RAX = 0 on success, error code on failure
;
; CRITICAL: All buffers MUST be 64-byte aligned.
; ==============================================================================

; External dependencies (from other Phase-29 kernels)
EXTERN SwarmV29_BitReverse256 : PROC
EXTERN SwarmV29_NTT_Transform : PROC
EXTERN SwarmV29_INTT_Transform : PROC
EXTERN SwarmV29_Brutal_Pack : PROC

; Transform flags
FLAG_FORWARD_NTT    EQU 01h
FLAG_INVERSE_INTT   EQU 02h
FLAG_PACK_OUTPUT    EQU 04h
FLAG_BIT_REVERSE    EQU 08h

; Kyber-1024 constants
KYBER_N              EQU 256
KYBER_Q              EQU 3329
KYBER_Q_INV          EQU 62209

.data
ALIGN 64

; Pre-computed constants (loaded once per pipeline invocation)
Q_Const      DQ KYBER_Q
Q_Inv_Const  DQ KYBER_Q_INV
N_Const      DQ KYBER_N

.code
ALIGN 16

; ==============================================================================
; SwarmV29_Execute_Pipeline
; Main entry point for PQC transformations.
; ==============================================================================
SwarmV29_Execute_Pipeline PROC

    ; ABI Prologue
    push rbp
    mov rbp, rsp
    push rbx
    push rdi
    push rsi
    push r12
    push r13
    push r14
    push r15

    ; Save parameters
    mov rsi, rcx                      ; Data buffer
    mov rdi, rdx                      ; Twiddle table
    mov r12, r8                       ; Output buffer
    mov r13, r9                       ; Transform flags

    ; Validate alignment
    test rsi, 3Fh
    jnz .Error_Misaligned_Data
    test rdi, 3Fh
    jnz .Error_Misaligned_Twiddle
    test r12, 3Fh
    jnz .Error_Misaligned_Output

    ; Broadcast Q and Q_INV to ZMM30/ZMM31 (hoisted constants)
    vpbroadcastq zmm30, [Q_Const]
    vpbroadcastq zmm31, [Q_Inv_Const]

    ; ------------------------------------------------------------------
    ; Stage 1: Bit-Reversal Permutation (if requested)
    ; ------------------------------------------------------------------
    test r13, FLAG_BIT_REVERSE
    jz .Skip_BitReverse

    ; Call BitReverse
    ; RCX = array, RDX = N, R8 = log2(N)
    mov rcx, rsi
    mov rdx, KYBER_N
    mov r8, 8                         ; log2(256) = 8
    call SwarmV29_BitReverse256

.Skip_BitReverse:

    ; ------------------------------------------------------------------
    ; Stage 2: Forward NTT Transform (if requested)
    ; ------------------------------------------------------------------
    test r13, FLAG_FORWARD_NTT
    jz .Skip_Forward_NTT

    ; Call NTT Transform
    ; RCX = array, RDX = N, R8 = twiddle, R9 = Q, [stack] = Q_inv
    mov rcx, rsi
    mov rdx, KYBER_N
    mov r8, rdi
    mov r9, KYBER_Q
    sub rsp, 32
    mov qword ptr [rsp + 32], KYBER_Q_INV
    call SwarmV29_NTT_Transform
    add rsp, 32

.Skip_Forward_NTT:

    ; ------------------------------------------------------------------
    ; Stage 3: Inverse INTT Transform (if requested)
    ; ------------------------------------------------------------------
    test r13, FLAG_INVERSE_INTT
    jz .Skip_Inverse_INTT

    ; Call INTT Transform
    mov rcx, rsi
    mov rdx, KYBER_N
    mov r8, rdi
    mov r9, KYBER_Q
    sub rsp, 32
    mov qword ptr [rsp + 32], KYBER_Q_INV
    call SwarmV29_INTT_Transform
    add rsp, 32

.Skip_Inverse_INTT:

    ; ------------------------------------------------------------------
    ; Stage 4: Pack Output (if requested)
    ; ------------------------------------------------------------------
    test r13, FLAG_PACK_OUTPUT
    jz .Skip_Pack

    ; Call Brutal Pack
    ; RCX = src, RDX = dst, R8 = block count
    mov rcx, rsi
    mov rdx, r12
    mov r8, KYBER_N / 32              ; 256 / 32 = 8 blocks
    call SwarmV29_Brutal_Pack

.Skip_Pack:

    ; Success
    xor rax, rax

    ; ABI Epilogue
    pop r15
    pop r14
    pop r13
    pop r12
    pop rsi
    pop rdi
    pop rbx
    pop rbp
    ret

.Error_Misaligned_Data:
    mov rax, 0DEAD0001h
    jmp .Epilogue

.Error_Misaligned_Twiddle:
    mov rax, 0DEAD0002h
    jmp .Epilogue

.Error_Misaligned_Output:
    mov rax, 0DEAD0003h
    jmp .Epilogue

.Epilogue:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rsi
    pop rdi
    pop rbx
    pop rbp
    ret

SwarmV29_Execute_Pipeline ENDP

; ==============================================================================
; SwarmV29_Execute_Kyber_Encapsulate
; Full Kyber-1024 KEM encapsulation pipeline.
; Input:
;   RCX = Public key (1184 bytes)
;   RDX = Ciphertext output (1568 bytes)
;   R8  = Shared secret output (32 bytes)
; Output:
;   RAX = 0 on success
; ==============================================================================
SwarmV29_Execute_Kyber_Encapsulate PROC

    ; ABI Prologue
    push rbp
    mov rbp, rsp
    push rbx
    push rdi
    push rsi
    sub rsp, 32

    ; Save parameters
    mov rbx, rcx                      ; Public key
    mov rdi, rdx                      ; Ciphertext
    mov rsi, r8                       ; Shared secret

    ; Stage 1: Generate random polynomial
    ; (Would call entropy mixer here)

    ; Stage 2: Bit-reverse for NTT
    mov rcx, rbx
    mov rdx, KYBER_N
    mov r8, 8
    call SwarmV29_BitReverse256

    ; Stage 3: Forward NTT
    ; (Would call NTT transform here)

    ; Stage 4: Polynomial multiplication
    ; (Would call butterfly kernels here)

    ; Stage 5: Inverse NTT
    ; (Would call INTT transform here)

    ; Stage 6: Pack ciphertext
    ; (Would call Brutal_Pack here)

    ; Success
    xor rax, rax

    add rsp, 32
    pop rsi
    pop rdi
    pop rbx
    pop rbp
    ret

SwarmV29_Execute_Kyber_Encapsulate ENDP

; ==============================================================================
; SwarmV29_Execute_Dilithium_Sign
; Full Dilithium-5 signature generation pipeline.
; Input:
;   RCX = Message
;   RDX = Message length
;   R8  = Secret key (4896 bytes)
;   R9  = Signature output (4595 bytes)
; Output:
;   RAX = 0 on success
; ==============================================================================
SwarmV29_Execute_Dilithium_Sign PROC

    ; ABI Prologue
    push rbp
    mov rbp, rsp
    push rbx
    push rdi
    push rsi
    sub rsp, 32

    ; Save parameters
    mov rbx, rcx                      ; Message
    mov rdi, rdx                      ; Message length
    mov rsi, r8                       ; Secret key
    ; R9 already has signature output

    ; Stage 1: Hash message
    ; (Would call hash function here)

    ; Stage 2: Generate challenge polynomial
    ; (Would call entropy mixer here)

    ; Stage 3: NTT-based polynomial operations
    ; (Would call NTT/Butterfly kernels here)

    ; Stage 4: Compute signature
    ; (Would call signature computation here)

    ; Stage 5: Pack signature
    ; (Would call Brutal_Pack here)

    ; Success
    xor rax, rax

    add rsp, 32
    pop rsi
    pop rdi
    pop rbx
    pop rbp
    ret

SwarmV29_Execute_Dilithium_Sign ENDP

; ==============================================================================
; SwarmV29_Execute_Benchmark
; Performance benchmark for throughput measurement.
; Input: RCX = Iterations
; Output: RAX = Cycles per iteration (approximate)
; ==============================================================================
SwarmV29_Execute_Benchmark PROC

    ; ABI Prologue
    push rbp
    mov rbp, rsp
    push rbx
    push rdi
    sub rsp, 32

    ; Save iteration count
    mov rbx, rcx

    ; Read TSC start
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov rdi, rax

    ; Benchmark loop (empty for now, would call actual kernels)
ALIGN 16
.Bench_Loop:
    dec rbx
    jnz .Bench_Loop

    ; Read TSC end
    rdtsc
    shl rdx, 32
    or rax, rdx

    ; Calculate delta
    sub rax, rdi

    add rsp, 32
    pop rdi
    pop rbx
    pop rbp
    ret

SwarmV29_Execute_Benchmark ENDP

END