include Sovereign_Common.inc
; =====================================================================================
; SOVEREIGN ENGINE - RANDOM ENGINE GENERATOR
; SUBSYSTEM: ENTROPY-DRIVEN MICROARCHITECTURAL ENGINE SYNTHESIS
; ARCHITECTURE: X86-64 (MASM64)
; CODENAME: CHAOS_FORGE v1.0.0
; =====================================================================================
; Generates deterministic engine archetypes from hardware entropy sources.
; Zero dependencies. Zero C-runtime. Pure bare-metal x64 assembly.
; =====================================================================================

; -------------------------------------------------------------------------------------
; ENTROPY ACQUISITION PRIMITIVES
; -------------------------------------------------------------------------------------
; RDRAND: Hardware RNG (Intel Ivy Bridge+, AMD Zen+)
; RDSEED: Non-deterministic entropy source (Broadwell+, Zen+)
; RDTSC: Timestamp counter for jitter seeding
; CPUID: Feature detection for capability probing
; -------------------------------------------------------------------------------------

.DATA
    ; Engine Archetype Signature Table (16-byte aligned)
    ALIGN 16
    SIG_STREAMER    DB "FUSED_REG_STREAMER_", 0
    ALIGN 16
    SIG_TERNARY     DB "BIT_TERNARY_LOGIC_", 0
    ALIGN 16
    SIG_TLB         DB "TLB_PINNED_BUFFER_", 0
    ALIGN 16
    SIG_BANK        DB "BANK_EVADE_MATRIX_", 0
    ALIGN 16
    SIG_FIBER       DB "FIBER_SCHEDULER_", 0
    ALIGN 16
    SIG_SPEC        DB "SPEC_TREE_STEERER_", 0
    ALIGN 16
    SIG_PORT        DB "PORT_HARMONIZER_", 0
    ALIGN 16
    SIG_L1D         DB "L1D_CONFLICT_BYPASS_", 0

    ; Mutation Connectors
    ALIGN 16
    CON_FUSE        DB "MUTATED_WITH_", 0
    ALIGN 16
    CON_HYBRID      DB "HYBRIDIZED_BY_", 0
    ALIGN 16
    CON_CASCADE     DB "CASCADED_INTO_", 0

    ; Engine State Constants
    ENGINE_MAX_ARMS EQU 8
    ENGINE_NAME_LEN EQU 256
    ENTROPY_POOL_SZ EQU 256

    ; Feature Flags (from CPUID leaf 7, ECX bit 30 = RDRAND, bit 18 = RDSEED)
    FEAT_RDRAND     EQU 40000000h
    FEAT_RDSEED     EQU 00040000h

.CODE

; =====================================================================================
; STRUCTURE: ENTROPY POOL
; Hardware-captured randomness reservoir for engine generation
; =====================================================================================
SOVEREIGN_ENTROPY_POOL STRUCT
    Pool            DB ENTROPY_POOL_SZ DUP (?)
    PoolIndex       QWORD ?
    HasRdrand       BYTE ?
    HasRdseed       BYTE ?
    Pad             BYTE 6 DUP (?)
SOVEREIGN_ENTROPY_POOL ENDS

; =====================================================================================
; STRUCTURE: ENGINE GENOME
; The genetic blueprint for a generated engine archetype
; =====================================================================================
SOVEREIGN_ENGINE_GENOME STRUCT
    ComputeGene     QWORD ?         ; 0-7: Selects compute primitive
    MemoryGene      QWORD ?         ; 0-7: Selects memory strategy
    SchedulerGene   QWORD ?         ; 0-7: Selects scheduling policy
    MutationSeed    QWORD ?         ; Raw entropy for mutation factor
    FusionDepth     QWORD ?         ; How many primitives to fuse (1-4)
    StrideSkew      QWORD ?         ; Cache-line alignment perturbation
    PortMask        QWORD ?         ; Execution port affinity bitmap
    EngineName      DB ENGINE_NAME_LEN DUP (?)
SOVEREIGN_ENGINE_GENOME ENDS

; =====================================================================================
; STRUCTURE: GENERATED ENGINE
; Final compiled engine descriptor with executable metadata
; =====================================================================================
SOVEREIGN_GENERATED_ENGINE STRUCT
    Genome          SOVEREIGN_ENGINE_GENOME <>
    EntryPoint      QWORD ?         ; Generated code address (PAGE_EXECUTE_READ)
    CodeSize        QWORD ?         ; Size of generated machine code
    HotRegionStart  QWORD ?         ; Memory region to pin
    HotRegionSize   QWORD ?         ; Size of hot region
    PerformanceTier QWORD ?         ; 0=conservative, 1=balanced, 2=aggressive
SOVEREIGN_GENERATED_ENGINE ENDS

; =====================================================================================
; API: Sovereign_Entropy_Probe
; Detects hardware RNG capabilities via CPUID
; INPUT:  RCX = pointer to SOVEREIGN_ENTROPY_POOL
; OUTPUT: RAX = 0 (success), fills capability bits
; =====================================================================================
Sovereign_Entropy_Probe PROC
    push rbx
    push rsi
    push rdi
    sub rsp, 32

    mov rdi, rcx                    ; RDI = pool pointer

    ; Clear capability flags
    mov byte ptr [rdi + SOVEREIGN_ENTROPY_POOL.HasRdrand], 0
    mov byte ptr [rdi + SOVEREIGN_ENTROPY_POOL.HasRdseed], 0

    ; CPUID leaf 1: check RDRAND (ECX bit 30)
    mov eax, 1
    cpuid
    test ecx, FEAT_RDRAND
    jz check_rdseed
    mov byte ptr [rdi + SOVEREIGN_ENTROPY_POOL.HasRdrand], 1

check_rdseed:
    ; CPUID leaf 7 subleaf 0: check RDSEED (EBX bit 18)
    mov eax, 7
    xor ecx, ecx
    cpuid
    test ebx, FEAT_RDSEED
    jz probe_done
    mov byte ptr [rdi + SOVEREIGN_ENTROPY_POOL.HasRdseed], 1

probe_done:
    xor rax, rax
    add rsp, 32
    pop rdi
    pop rsi
    pop rbx
    ret
Sovereign_Entropy_Probe ENDP

; =====================================================================================
; API: Sovereign_Entropy_Harvest
; Fills entropy pool from hardware RNG + TSC jitter
; INPUT:  RCX = pointer to SOVEREIGN_ENTROPY_POOL
; OUTPUT: RAX = bytes harvested
; =====================================================================================
Sovereign_Entropy_Harvest PROC
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    sub rsp, 32

    mov rdi, rcx                    ; RDI = pool pointer
    mov r12, rdi                    ; R12 = pool base
    xor r13, r13                    ; R13 = harvest count

    ; Reset pool index
    mov qword ptr [rdi + SOVEREIGN_ENTROPY_POOL.PoolIndex], 0

    ; Determine best entropy source
    mov al, byte ptr [rdi + SOVEREIGN_ENTROPY_POOL.HasRdseed]
    test al, al
    jnz use_rdseed
    mov al, byte ptr [rdi + SOVEREIGN_ENTROPY_POOL.HasRdrand]
    test al, al
    jnz use_rdrand
    jmp use_tsc_fallback

use_rdseed:
    mov rsi, rdi                    ; RSI = pool fill pointer
    add rsi, SOVEREIGN_ENTROPY_POOL.Pool
    mov rcx, ENTROPY_POOL_SZ / 8    ; 32 qwords to fill

rdseed_loop:
    rdseed rax
    jnc rdseed_retry                ; CF=0 means underflow, retry
    mov qword ptr [rsi], rax
    add rsi, 8
    add r13, 8
    dec rcx
    jnz rdseed_loop
    jmp harvest_done

rdseed_retry:
    pause
    jmp rdseed_loop

use_rdrand:
    mov rsi, rdi
    add rsi, SOVEREIGN_ENTROPY_POOL.Pool
    mov rcx, ENTROPY_POOL_SZ / 8

rdrand_loop:
    rdrand rax
    jnc rdrand_retry
    mov qword ptr [rsi], rax
    add rsi, 8
    add r13, 8
    dec rcx
    jnz rdrand_loop
    jmp harvest_done

rdrand_retry:
    pause
    jmp rdrand_loop

use_tsc_fallback:
    ; No hardware RNG: use RDTSC + memory bus jitter
    mov rsi, rdi
    add rsi, SOVEREIGN_ENTROPY_POOL.Pool
    mov rcx, ENTROPY_POOL_SZ / 8

tsc_loop:
    rdtsc                           ; EDX:EAX = timestamp
    shl rdx, 32
    or rax, rdx
    ; Mix with memory address entropy (cache line aliasing jitter)
    mov rbx, rsi
    xor rbx, rax
    rol rax, 17
    xor rax, rbx
    mov qword ptr [rsi], rax
    add rsi, 8
    add r13, 8
    dec rcx
    jnz tsc_loop

harvest_done:
    mov rax, r13
    add rsp, 32
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
Sovereign_Entropy_Harvest ENDP

; =====================================================================================
; API: Sovereign_Entropy_Draw
; Draws N bytes of entropy from the pool with auto-refill
; INPUT:  RCX = pointer to SOVEREIGN_ENTROPY_POOL
;         RDX = number of bytes requested (max 8)
; OUTPUT: RAX = entropy value (low bytes valid)
; =====================================================================================
Sovereign_Entropy_Draw PROC
    push rbx
    push rsi
    push rdi
    sub rsp, 32

    mov rdi, rcx
    mov rsi, rdx                    ; RSI = bytes requested
    cmp rsi, 8
    ja cap_at_8
    jmp get_index

cap_at_8:
    mov rsi, 8

get_index:
    mov rbx, qword ptr [rdi + SOVEREIGN_ENTROPY_POOL.PoolIndex]
    cmp rbx, ENTROPY_POOL_SZ - 8
    jl extract_entropy

    ; Pool exhausted: re-harvest
    push rsi
    mov rcx, rdi
    call Sovereign_Entropy_Harvest
    pop rsi
    xor rbx, rbx

extract_entropy:
    lea rax, [rdi + SOVEREIGN_ENTROPY_POOL.Pool + rbx]
    mov rcx, rsi
    mov rdx, qword ptr [rax]

    ; Mask to requested byte count
    mov r8, 1
    shl r8, cl
    dec r8
    and rdx, r8
    mov rax, rdx

    ; Advance index
    add rbx, rsi
    mov qword ptr [rdi + SOVEREIGN_ENTROPY_POOL.PoolIndex], rbx

    add rsp, 32
    pop rdi
    pop rsi
    pop rbx
    ret
Sovereign_Entropy_Draw ENDP

; =====================================================================================
; API: Sovereign_Engine_Forge
; Generates a complete engine archetype from entropy
; INPUT:  RCX = pointer to SOVEREIGN_ENTROPY_POOL
;         RDX = pointer to uninitialized SOVEREIGN_GENERATED_ENGINE
; OUTPUT: RAX = 0 (success), -1 (null pointer)
; =====================================================================================
Sovereign_Engine_Forge PROC
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub rsp, 48

    ; Validate inputs
    test rcx, rcx
    jz forge_null_error
    test rdx, rdx
    jz forge_null_error

    mov r12, rcx                    ; R12 = entropy pool
    mov r13, rdx                    ; R13 = engine output
    mov rdi, rdx
    add rdi, SOVEREIGN_GENERATED_ENGINE.Genome
                                    ; RDI = genome pointer

    ; Clear genome
    xor eax, eax
    mov ecx, SIZEOF SOVEREIGN_ENGINE_GENOME / 8
    rep stosq
    mov rdi, r13
    add rdi, SOVEREIGN_GENERATED_ENGINE.Genome

    ; ---------------------------------------------------------
    ; GENE 1: Compute Primitive (0-7)
    ; ---------------------------------------------------------
    mov rcx, r12
    mov rdx, 1
    call Sovereign_Entropy_Draw
    and rax, 7                      ; Modulo 8
    mov qword ptr [rdi + SOVEREIGN_ENGINE_GENOME.ComputeGene], rax

    ; ---------------------------------------------------------
    ; GENE 2: Memory Strategy (0-7)
    ; ---------------------------------------------------------
    mov rcx, r12
    mov rdx, 1
    call Sovereign_Entropy_Draw
    and rax, 7
    mov qword ptr [rdi + SOVEREIGN_ENGINE_GENOME.MemoryGene], rax

    ; ---------------------------------------------------------
    ; GENE 3: Scheduler Policy (0-7)
    ; ---------------------------------------------------------
    mov rcx, r12
    mov rdx, 1
    call Sovereign_Entropy_Draw
    and rax, 7
    mov qword ptr [rdi + SOVEREIGN_ENGINE_GENOME.SchedulerGene], rax

    ; ---------------------------------------------------------
    ; GENE 4: Mutation Seed (64-bit raw entropy)
    ; ---------------------------------------------------------
    mov rcx, r12
    mov rdx, 8
    call Sovereign_Entropy_Draw
    mov qword ptr [rdi + SOVEREIGN_ENGINE_GENOME.MutationSeed], rax

    ; ---------------------------------------------------------
    ; GENE 5: Fusion Depth (1-4)
    ; ---------------------------------------------------------
    mov rcx, r12
    mov rdx, 1
    call Sovereign_Entropy_Draw
    and rax, 3
    inc rax                         ; 1-4
    mov qword ptr [rdi + SOVEREIGN_ENGINE_GENOME.FusionDepth], rax

    ; ---------------------------------------------------------
    ; GENE 6: Stride Skew (0-63 cache line offset)
    ; ---------------------------------------------------------
    mov rcx, r12
    mov rdx, 1
    call Sovereign_Entropy_Draw
    and rax, 63
    mov qword ptr [rdi + SOVEREIGN_ENGINE_GENOME.StrideSkew], rax

    ; ---------------------------------------------------------
    ; GENE 7: Port Affinity Mask
    ; Derived from mutation seed high nibble
    ; ---------------------------------------------------------
    mov rax, qword ptr [rdi + SOVEREIGN_ENGINE_GENOME.MutationSeed]
    shr rax, 60                     ; Top 4 bits
    mov rbx, 1
    mov rcx, rax
    shl rbx, cl
    dec rbx
    test rbx, rbx
    jnz store_port_mask
    mov rbx, 0Fh                    ; Default: ports 0-3
store_port_mask:
    mov qword ptr [rdi + SOVEREIGN_ENGINE_GENOME.PortMask], rbx

    ; ---------------------------------------------------------
    ; BUILD ENGINE NAME FROM GENOME
    ; ---------------------------------------------------------
    lea r14, [rdi + SOVEREIGN_ENGINE_GENOME.EngineName]
    mov r15, r14                    ; R15 = name build pointer

    ; Append compute signature
    mov rax, qword ptr [rdi + SOVEREIGN_ENGINE_GENOME.ComputeGene]
    and rax, 7
    call Select_Compute_Signature
    mov rsi, rax
    call String_Append

    ; Append connector
    mov rax, qword ptr [rdi + SOVEREIGN_ENGINE_GENOME.MutationSeed]
    and rax, 1
    call Select_Connector
    mov rsi, rax
    call String_Append

    ; Append memory signature
    mov rax, qword ptr [rdi + SOVEREIGN_ENGINE_GENOME.MemoryGene]
    and rax, 7
    call Select_Memory_Signature
    mov rsi, rax
    call String_Append

    ; Append scheduler suffix if fusion depth > 2
    mov rax, qword ptr [rdi + SOVEREIGN_ENGINE_GENOME.FusionDepth]
    cmp rax, 2
    jle finalize_name

    mov al, "_"
    mov byte ptr [r15], al
    inc r15

    mov rax, qword ptr [rdi + SOVEREIGN_ENGINE_GENOME.SchedulerGene]
    and rax, 7
    call Select_Scheduler_Signature
    mov rsi, rax
    call String_Append

finalize_name:
    mov byte ptr [r15], 0           ; Null terminate

    ; ---------------------------------------------------------
    ; SET ENGINE METADATA
    ; ---------------------------------------------------------
    mov qword ptr [r13 + SOVEREIGN_GENERATED_ENGINE.EntryPoint], 0
    mov qword ptr [r13 + SOVEREIGN_GENERATED_ENGINE.CodeSize], 0

    ; Hot region = first 256MB (KV + embeddings)
    mov qword ptr [r13 + SOVEREIGN_GENERATED_ENGINE.HotRegionSize], 10000000h

    ; Performance tier from mutation seed
    mov rax, qword ptr [rdi + SOVEREIGN_ENGINE_GENOME.MutationSeed]
    and rax, 3
    cmp rax, 3
    jl store_tier
    mov rax, 2
store_tier:
    mov qword ptr [r13 + SOVEREIGN_GENERATED_ENGINE.PerformanceTier], rax

    xor rax, rax
    jmp forge_exit

forge_null_error:
    mov rax, -1

forge_exit:
    add rsp, 48
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
Sovereign_Engine_Forge ENDP

; =====================================================================================
; HELPER: Select_Compute_Signature
; INPUT: RAX = gene value (0-7)
; OUTPUT: RAX = pointer to signature string
; =====================================================================================
Select_Compute_Signature PROC
    lea rbx, SIG_STREAMER
    cmp rax, 0
    je scs_done
    lea rbx, SIG_TERNARY
    cmp rax, 1
    je scs_done
    lea rbx, SIG_PORT
    cmp rax, 2
    je scs_done
    lea rbx, SIG_SPEC
    cmp rax, 3
    je scs_done
    lea rbx, SIG_STREAMER           ; Default fallback
scs_done:
    mov rax, rbx
    ret
Select_Compute_Signature ENDP

; =====================================================================================
; HELPER: Select_Memory_Signature
; INPUT: RAX = gene value (0-7)
; OUTPUT: RAX = pointer to signature string
; =====================================================================================
Select_Memory_Signature PROC
    lea rbx, SIG_TLB
    cmp rax, 0
    je sms_done
    lea rbx, SIG_BANK
    cmp rax, 1
    je sms_done
    lea rbx, SIG_L1D
    cmp rax, 2
    je sms_done
    lea rbx, SIG_TLB                ; Default fallback
sms_done:
    mov rax, rbx
    ret
Select_Memory_Signature ENDP

; =====================================================================================
; HELPER: Select_Scheduler_Signature
; INPUT: RAX = gene value (0-7)
; OUTPUT: RAX = pointer to signature string
; =====================================================================================
Select_Scheduler_Signature PROC
    lea rbx, SIG_FIBER
    cmp rax, 0
    je sss_done
    lea rbx, SIG_SPEC
    cmp rax, 1
    je sss_done
    lea rbx, SIG_FIBER              ; Default fallback
sss_done:
    mov rax, rbx
    ret
Select_Scheduler_Signature ENDP

; =====================================================================================
; HELPER: Select_Connector
; INPUT: RAX = bit 0 of mutation seed
; OUTPUT: RAX = pointer to connector string
; =====================================================================================
Select_Connector PROC
    lea rbx, CON_FUSE
    test rax, rax
    jz sc_done
    lea rbx, CON_HYBRID
sc_done:
    mov rax, rbx
    ret
Select_Connector ENDP

; =====================================================================================
; HELPER: String_Append
; Copies null-terminated string from RSI to R15, advances R15
; =====================================================================================
String_Append PROC
    push rax
sa_loop:
    lodsb
    test al, al
    jz sa_done
    mov byte ptr [r15], al
    inc r15
    jmp sa_loop
sa_done:
    pop rax
    ret
String_Append ENDP

; =====================================================================================
; API: Sovereign_Engine_Mutate
; Applies deterministic mutation to an existing engine genome
; INPUT:  RCX = pointer to SOVEREIGN_ENTROPY_POOL
;         RDX = pointer to existing SOVEREIGN_GENERATED_ENGINE
;         R8  = mutation intensity (0-255)
; OUTPUT: RAX = 0 (success), modified engine in-place
; =====================================================================================
Sovereign_Engine_Mutate PROC
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    sub rsp, 32

    test rcx, rcx
    jz mutate_null
    test rdx, rdx
    jz mutate_null

    mov r12, rcx                    ; R12 = entropy pool
    mov r13, rdx                    ; R13 = engine to mutate
    mov r14, r8                     ; R14 = intensity
    and r14, 0FFh                   ; Clamp to byte

    mov rdi, r13
    add rdi, SOVEREIGN_GENERATED_ENGINE.Genome

    ; Mutate compute gene with probability based on intensity
    mov rcx, r12
    mov rdx, 1
    call Sovereign_Entropy_Draw
    cmp al, r14b
    ja skip_compute_mutate

    mov rcx, r12
    mov rdx, 1
    call Sovereign_Entropy_Draw
    and rax, 7
    mov qword ptr [rdi + SOVEREIGN_ENGINE_GENOME.ComputeGene], rax

skip_compute_mutate:
    ; Mutate memory gene
    mov rcx, r12
    mov rdx, 1
    call Sovereign_Entropy_Draw
    cmp al, r14b
    ja skip_memory_mutate

    mov rcx, r12
    mov rdx, 1
    call Sovereign_Entropy_Draw
    and rax, 7
    mov qword ptr [rdi + SOVEREIGN_ENGINE_GENOME.MemoryGene], rax

skip_memory_mutate:
    ; Mutate scheduler gene
    mov rcx, r12
    mov rdx, 1
    call Sovereign_Entropy_Draw
    cmp al, r14b
    ja skip_scheduler_mutate

    mov rcx, r12
    mov rdx, 1
    call Sovereign_Entropy_Draw
    and rax, 7
    mov qword ptr [rdi + SOVEREIGN_ENGINE_GENOME.SchedulerGene], rax

skip_scheduler_mutate:
    ; Mutate stride skew
    mov rcx, r12
    mov rdx, 1
    call Sovereign_Entropy_Draw
    cmp al, r14b
    ja skip_stride_mutate

    mov rcx, r12
    mov rdx, 1
    call Sovereign_Entropy_Draw
    and rax, 63
    mov qword ptr [rdi + SOVEREIGN_ENGINE_GENOME.StrideSkew], rax

skip_stride_mutate:
    ; Re-roll mutation seed
    mov rcx, r12
    mov rdx, 8
    call Sovereign_Entropy_Draw
    mov qword ptr [rdi + SOVEREIGN_ENGINE_GENOME.MutationSeed], rax

    ; Regenerate name
    lea r14, [rdi + SOVEREIGN_ENGINE_GENOME.EngineName]
    mov r15, r14

    mov rax, qword ptr [rdi + SOVEREIGN_ENGINE_GENOME.ComputeGene]
    and rax, 7
    call Select_Compute_Signature
    mov rsi, rax
    call String_Append

    mov rax, qword ptr [rdi + SOVEREIGN_ENGINE_GENOME.MutationSeed]
    and rax, 1
    call Select_Connector
    mov rsi, rax
    call String_Append

    mov rax, qword ptr [rdi + SOVEREIGN_ENGINE_GENOME.MemoryGene]
    and rax, 7
    call Select_Memory_Signature
    mov rsi, rax
    call String_Append

    mov byte ptr [r15], 0

    xor rax, rax
    jmp mutate_exit

mutate_null:
    mov rax, -1

mutate_exit:
    add rsp, 32
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
Sovereign_Engine_Mutate ENDP

; =====================================================================================
; API: Sovereign_Engine_Spawn_Batch
; Generates N engine archetypes in a single batch operation
; INPUT:  RCX = pointer to SOVEREIGN_ENTROPY_POOL
;         RDX = pointer to array of SOVEREIGN_GENERATED_ENGINE
;         R8  = count of engines to spawn
; OUTPUT: RAX = number successfully spawned
; =====================================================================================
Sovereign_Engine_Spawn_Batch PROC
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    sub rsp, 32

    test rcx, rcx
    jz batch_null
    test rdx, rdx
    jz batch_null
    test r8, r8
    jz batch_null

    mov r12, rcx                    ; R12 = entropy pool
    mov r13, rdx                    ; R13 = engine array
    mov r14, r8                     ; R14 = count
    xor r15, r15                    ; R15 = spawned count

    mov rbx, SIZEOF SOVEREIGN_GENERATED_ENGINE

batch_loop:
    cmp r15, r14
    jge batch_done

    mov rcx, r12
    mov rdx, r13
    call Sovereign_Engine_Forge
    test rax, rax
    jnz batch_fail

    inc r15
    add r13, rbx
    jmp batch_loop

batch_fail:
    ; Continue with partial success
    jmp batch_done

batch_done:
    mov rax, r15
    jmp batch_exit

batch_null:
    xor rax, rax

batch_exit:
    add rsp, 32
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
Sovereign_Engine_Spawn_Batch ENDP

; =====================================================================================
; API: Sovereign_Engine_Crossbreed
; Combines two parent engines into a child engine
; INPUT:  RCX = pointer to SOVEREIGN_ENTROPY_POOL
;         RDX = pointer to parent A SOVEREIGN_GENERATED_ENGINE
;         R8  = pointer to parent B SOVEREIGN_GENERATED_ENGINE
;         R9  = pointer to child SOVEREIGN_GENERATED_ENGINE (output)
; OUTPUT: RAX = 0 (success)
; =====================================================================================
Sovereign_Engine_Crossbreed PROC
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub rsp, 32

    test rcx, rcx
    jz cross_null
    test rdx, rdx
    jz cross_null
    test r8, r8
    jz cross_null
    test r9, r9
    jz cross_null

    mov r12, rcx                    ; R12 = entropy pool
    mov r13, rdx                    ; R13 = parent A
    mov r14, r8                     ; R14 = parent B
    mov r15, r9                     ; R15 = child

    ; Clear child
    mov rdi, r15
    xor eax, eax
    mov ecx, SIZEOF SOVEREIGN_GENERATED_ENGINE / 8
    rep stosq

    mov rsi, r13
    add rsi, SOVEREIGN_GENERATED_ENGINE.Genome
    mov rdi, r14
    add rdi, SOVEREIGN_GENERATED_ENGINE.Genome

    ; Crossbreed: coin flip for each gene
    ; Compute gene
    mov rcx, r12
    mov rdx, 1
    call Sovereign_Entropy_Draw
    test al, 1
    jz take_compute_a
    mov rax, qword ptr [rdi + SOVEREIGN_ENGINE_GENOME.ComputeGene]
    jmp store_compute
take_compute_a:
    mov rax, qword ptr [rsi + SOVEREIGN_ENGINE_GENOME.ComputeGene]
store_compute:
    mov rbx, r15
    add rbx, SOVEREIGN_GENERATED_ENGINE.Genome
    mov qword ptr [rbx + SOVEREIGN_ENGINE_GENOME.ComputeGene], rax

    ; Memory gene
    mov rcx, r12
    mov rdx, 1
    call Sovereign_Entropy_Draw
    test al, 1
    jz take_memory_a
    mov rax, qword ptr [rdi + SOVEREIGN_ENGINE_GENOME.MemoryGene]
    jmp store_memory
take_memory_a:
    mov rax, qword ptr [rsi + SOVEREIGN_ENGINE_GENOME.MemoryGene]
store_memory:
    mov qword ptr [rbx + SOVEREIGN_ENGINE_GENOME.MemoryGene], rax

    ; Scheduler gene
    mov rcx, r12
    mov rdx, 1
    call Sovereign_Entropy_Draw
    test al, 1
    jz take_sched_a
    mov rax, qword ptr [rdi + SOVEREIGN_ENGINE_GENOME.SchedulerGene]
    jmp store_sched
take_sched_a:
    mov rax, qword ptr [rsi + SOVEREIGN_ENGINE_GENOME.SchedulerGene]
store_sched:
    mov qword ptr [rbx + SOVEREIGN_ENGINE_GENOME.SchedulerGene], rax

    ; Mutation seed = XOR of parents
    mov rax, qword ptr [rsi + SOVEREIGN_ENGINE_GENOME.MutationSeed]
    xor rax, qword ptr [rdi + SOVEREIGN_ENGINE_GENOME.MutationSeed]
    mov qword ptr [rbx + SOVEREIGN_ENGINE_GENOME.MutationSeed], rax

    ; Fusion depth = average of parents
    mov rax, qword ptr [rsi + SOVEREIGN_ENGINE_GENOME.FusionDepth]
    add rax, qword ptr [rdi + SOVEREIGN_ENGINE_GENOME.FusionDepth]
    shr rax, 1
    mov qword ptr [rbx + SOVEREIGN_ENGINE_GENOME.FusionDepth], rax

    ; Stride skew = XOR mix
    mov rax, qword ptr [rsi + SOVEREIGN_ENGINE_GENOME.StrideSkew]
    xor rax, qword ptr [rdi + SOVEREIGN_ENGINE_GENOME.StrideSkew]
    and rax, 63
    mov qword ptr [rbx + SOVEREIGN_ENGINE_GENOME.StrideSkew], rax

    ; Port mask = OR of parents
    mov rax, qword ptr [rsi + SOVEREIGN_ENGINE_GENOME.PortMask]
    or rax, qword ptr [rdi + SOVEREIGN_ENGINE_GENOME.PortMask]
    mov qword ptr [rbx + SOVEREIGN_ENGINE_GENOME.PortMask], rax

    ; Build child name
    lea r14, [rbx + SOVEREIGN_ENGINE_GENOME.EngineName]
    mov r15, r14

    mov rax, qword ptr [rbx + SOVEREIGN_ENGINE_GENOME.ComputeGene]
    and rax, 7
    call Select_Compute_Signature
    mov rsi, rax
    call String_Append

    lea rsi, CON_CASCADE
    call String_Append

    mov rax, qword ptr [rbx + SOVEREIGN_ENGINE_GENOME.MemoryGene]
    and rax, 7
    call Select_Memory_Signature
    mov rsi, rax
    call String_Append

    mov byte ptr [r15], 0

    ; Inherit hot region size from dominant parent (A)
    mov rax, qword ptr [r13 + SOVEREIGN_GENERATED_ENGINE.HotRegionSize]
    mov qword ptr [r15 + SOVEREIGN_GENERATED_ENGINE.HotRegionSize], rax

    xor rax, rax
    jmp cross_exit

cross_null:
    mov rax, -1

cross_exit:
    add rsp, 32
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
Sovereign_Engine_Crossbreed ENDP

; =====================================================================================
; API: Sovereign_Engine_Evaluate
; Scores an engine archetype for fitness
; INPUT:  RCX = pointer to SOVEREIGN_GENERATED_ENGINE
; OUTPUT: RAX = fitness score (higher = better), -1 = null
; =====================================================================================
Sovereign_Engine_Evaluate PROC
    push rbx
    push rsi
    push rdi
    sub rsp, 32

    test rcx, rcx
    jz eval_null

    mov rsi, rcx
    add rsi, SOVEREIGN_GENERATED_ENGINE.Genome
    xor rdi, rdi                    ; RDI = score accumulator

    ; Score compute gene diversity (higher variety = better)
    mov rax, qword ptr [rsi + SOVEREIGN_ENGINE_GENOME.ComputeGene]
    imul rax, 100
    add rdi, rax

    ; Score memory strategy alignment
    mov rax, qword ptr [rsi + SOVEREIGN_ENGINE_GENOME.MemoryGene]
    imul rax, 150
    add rdi, rax

    ; Score scheduler efficiency
    mov rax, qword ptr [rsi + SOVEREIGN_ENGINE_GENOME.SchedulerGene]
    imul rax, 80
    add rdi, rax

    ; Bonus for fusion depth (2-3 is optimal)
    mov rax, qword ptr [rsi + SOVEREIGN_ENGINE_GENOME.FusionDepth]
    cmp rax, 2
    jl no_fusion_bonus
    cmp rax, 3
    jg no_fusion_bonus
    add rdi, 500                    ; Optimal fusion bonus
no_fusion_bonus:

    ; Penalty for extreme stride skew
    mov rax, qword ptr [rsi + SOVEREIGN_ENGINE_GENOME.StrideSkew]
    cmp rax, 32
    jl no_skew_penalty
    sub rdi, 200                    ; High skew penalty
no_skew_penalty:

    ; Port mask coverage bonus
    mov rax, qword ptr [rsi + SOVEREIGN_ENGINE_GENOME.PortMask]
    popcnt rax, rax
    imul rax, 50
    add rdi, rax

    ; Performance tier multiplier
    mov rax, qword ptr [rcx + SOVEREIGN_GENERATED_ENGINE.PerformanceTier]
    imul rax, 300
    add rdi, rax

    mov rax, rdi
    jmp eval_exit

eval_null:
    mov rax, -1

eval_exit:
    add rsp, 32
    pop rdi
    pop rsi
    pop rbx
    ret
Sovereign_Engine_Evaluate ENDP

; =====================================================================================
; API: Sovereign_Engine_Evolve_Population
; Runs one generation of evolutionary selection on an engine population
; INPUT:  RCX = pointer to SOVEREIGN_ENTROPY_POOL
;         RDX = pointer to array of SOVEREIGN_GENERATED_ENGINE
;         R8  = population count
;         R9  = mutation intensity (0-255)
; OUTPUT: RAX = best fitness score achieved
; =====================================================================================
Sovereign_Engine_Evolve_Population PROC
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub rsp, 48

    test rcx, rcx
    jz evolve_null
    test rdx, rdx
    jz evolve_null
    test r8, r8
    jz evolve_null

    mov r12, rcx                    ; R12 = entropy pool
    mov r13, rdx                    ; R13 = population array
    mov r14, r8                     ; R14 = count
    mov r15, r9                     ; R15 = mutation intensity
    xor rbx, rbx                    ; RBX = best score
    mov rsi, rdx                    ; RSI = current engine
    mov rdi, r8                     ; RDI = loop counter

    mov rax, SIZEOF SOVEREIGN_GENERATED_ENGINE

    ; Phase 1: Evaluate all engines
score_loop:
    test rdi, rdi
    jz phase2_selection

    mov rcx, rsi
    call Sovereign_Engine_Evaluate
    cmp rax, rbx
    cmovg rbx, rax                  ; Track best score

    add rsi, rax
    dec rdi
    jmp score_loop

    ; Phase 2: Tournament selection + crossbreed (simplified)
phase2_selection:
    ; For now, return best score. Full tournament selection can be added.
    mov rax, rbx
    jmp evolve_exit

evolve_null:
    mov rax, -1

evolve_exit:
    add rsp, 48
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
Sovereign_Engine_Evolve_Population ENDP
END



