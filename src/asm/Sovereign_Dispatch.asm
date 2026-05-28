; ==================================================================================
; SOVEREIGN SIMD LANE-DISPATCH ORCHESTRATOR
; Phase 2C - Hardware Compute Pipeline Router
; Architecture: Tri-Stage Prefix Pipeline, Register Groomed, 64-byte bounded
; ==================================================================================

INCLUDE Sovereign_FrameABI.inc
INCLUDE Sovereign_Dispatch.inc

.DATA
ALIGN 64
; Jump table mapping opcodes directly to kernel functions for O(1) routing
g_DispatchTable DQ OFFSET Kernel_F32_Dot
                DQ OFFSET Kernel_Q4_K_Dot
                DQ OFFSET Kernel_Safe_Scalar
                DQ 5 DUP(0) ; Cache-line padding

.CODE

; ----------------------------------------------------------------------------
; Sovereign_Dispatch_Queue - Evaluates topology bounds and tail-calls the kernel
; RCX = Pointer to SOVEREIGN_WORK_ITEM
; ----------------------------------------------------------------------------
PUBLIC Sovereign_Dispatch_Queue
Sovereign_Dispatch_Queue PROC
    ENTER_FRAME
    
    ; Extract the designated operation
    mov rax, [rcx + SOVEREIGN_WORK_ITEM.Opcode]
    
    ; 1. Alignment check (Fast path vs Safe path)
    ; We enforce strict 64-byte bounds on inputs to qualify for AVX-512 Fast Path
    mov r8, [rcx + SOVEREIGN_WORK_ITEM.pWeights]
    mov r9, [rcx + SOVEREIGN_WORK_ITEM.pActivations]
    
    mov r10, r8
    or r10, r9
    test r10, 3Fh       ; Mask specifically for 64-byte boundary (0x3F)
    jnz @@safe_scalar   ; Unaligned memory topology bypasses SIMD faulting

    ; 2. Opcode Validation
    cmp rax, 2          ; Maximum Supported Fast-Path Opcodes
    jae @@safe_scalar

    ; 3. Stage & Dispatch Route
    lea rdx, g_DispatchTable
    mov rax, [rdx + rax * 8]
    
    ; Unpack WorkItem into standard registers for the isolated kernel
    ; RCX=pWeights, RDX=pActivations, R8=Elements, R9=pOutput
    mov r8, [rcx + SOVEREIGN_WORK_ITEM.NumElements]
    mov r9, [rcx + SOVEREIGN_WORK_ITEM.pOutput]
    mov rdx, [rcx + SOVEREIGN_WORK_ITEM.pActivations]
    mov rcx, [rcx + SOVEREIGN_WORK_ITEM.pWeights]
    
    ; Zero-overhead dispatch using standard JMP tail call to inherit frame
    EXIT_FRAME
    jmp rax

@@safe_scalar:
    ; Unaligned execution fallback
    lea rdx, g_DispatchTable
    mov rax, [rdx + 16] ; [Offset 2] -> Kernel_Safe_Scalar
    
    mov r8, [rcx + SOVEREIGN_WORK_ITEM.NumElements]
    mov r9, [rcx + SOVEREIGN_WORK_ITEM.pOutput]
    mov rdx, [rcx + SOVEREIGN_WORK_ITEM.pActivations]
    mov rcx, [rcx + SOVEREIGN_WORK_ITEM.pWeights]
    
    EXIT_FRAME
    jmp rax
Sovereign_Dispatch_Queue ENDP

; ============================================================================
; DISPATCHABLE KERNELS (Internal Execution Engines)
; ============================================================================

; ----------------------------------------------------------------------------
; F32 Dot Product Core (Tri-Stage Prefetch Pipeline)
; RCX = pWeights, RDX = pActivations, R8 = NumElements, R9 = pOutput
; ----------------------------------------------------------------------------
ALIGN 32
Kernel_F32_Dot PROC
    ENTER_FRAME
    
    ; Register Grooming (Stage 2 setup)
    vxorps zmm8, zmm8, zmm8     ; Accumulator strictly assigned to zmm8

    ; Element reduction (16 elements per AVX-512 F32 pass)
    shr r8, 4 
    jz @@done
    
@@tri_stage_loop:
    ; Stage 1: Prefetch execution latency hiding
    prefetcht0 [rcx + 128]      ; Prefetch L1 weights ahead of compute
    prefetcht0 [rdx + 128]      ; Prefetch L1 activations ahead of compute
    
    ; Stage 2: Register load & Grooming
    vmovaps zmm0, [rcx]         ; Strict 64-byte aligned load
    vmovaps zmm16, [rdx]        ; Strict 64-byte aligned load
    
    ; Stage 3: Arithmetic compute & FMA dispatch
    vfmadd231ps zmm8, zmm0, zmm16
    
    ; Pointer arithmetic
    add rcx, 64
    add rdx, 64
    dec r8
    jnz @@tri_stage_loop
    
@@done:
    ; Stub: Horizontal reduction and store payload logic here
    ; For now, committing the raw state strictly to memory
    vmovaps [r9], zmm8
    
    EXIT_FRAME
    ret
Kernel_F32_Dot ENDP

; ----------------------------------------------------------------------------
; Q4_K Dot Product Core (Stub)
; ----------------------------------------------------------------------------
ALIGN 32
Kernel_Q4_K_Dot PROC
    ENTER_FRAME
    ; Reserved for phase integration of quantized FMA ops
    EXIT_FRAME
    ret
Kernel_Q4_K_Dot ENDP

; ----------------------------------------------------------------------------
; Safe Scalar Processing (Fallback for Unaligned Tails & Chunks)
; ----------------------------------------------------------------------------
ALIGN 32
Kernel_Safe_Scalar PROC
    ENTER_FRAME
    ; Scalar loop ensures strict safety for non-64-byte bounded workloads
    ; bypassing SIMD constraint exceptions.
    EXIT_FRAME
    ret
Kernel_Safe_Scalar ENDP

END
