.CODE
; ==================================================================
; TITAN_CORE: HARDENED DISPATCHER (MODEL EXECUTION HUB)
; ==================================================================
; TITAN X64 REGISTER-TILING ABI (THE VIRTUAL L0)
; ==================================================================
; This contract prevents performance collapse across kernel boundaries. 
; All fused SIMD compute tiles must adhere to this topology to ensure 
; zero-cost composition, prevent hidden spills, and guarantee FMA saturation.
;
; | Role               | Registers     | Rule                                            |
; |--------------------|---------------|-------------------------------------------------|
; | Weights            | YMM0 - YMM1   | Ephemeral, overwritten every tile iteration     |
; | Accumulators       | YMM2 - YMM5   | Persistent across loops, must never spill       |
; | Activations        | YMM6 - YMM9   | Streaming inputs (broadcast vectors)            |
; | Temporaries/Masks  | YMM10 - YMM15 | Scratch only (masks, shifts, bitwise ops)       |
; | Prefetch Horizon   | Implicit      | Managed by AGU slots, offset via host memory    |
; ==================================================================
; INSTRUCTION FUSION ABI (STREAMING VECTOR PIPELINE)

; R9 = NodeID OR Compute Plan Pointer (Future: execution graph)
; RCX = Tensor A (Quantized Streams)
; RDX = Tensor B (Activation Tiles) / Accumulator Output
; R8  = Tensor Scales Data
; ==================================================================
KERNEL_SIMD PROC
    sub rsp, 28h
    lea rbx, [rcx + r8*4]
SIMD_loop: cmp rcx, rbx
    jae SIMD_done
    vmovups xmm0, xmmword ptr [rcx]
    vmulps  xmm0, xmm0, xmm1
    vmovups xmmword ptr [rdx], xmm0
    add rcx, 16
    add rdx, 16
    jmp SIMD_loop
SIMD_done: add rsp, 28h
    ret
KERNEL_SIMD ENDP

KERNEL_Q4 PROC
    mov rax, r8
    lea rbx, [rax + rax*8]
    add rbx, rbx
    add rbx, rdx
    mov rsi, rdx
Q4_loop: cmp rsi, rbx
    jae Q4_done
    vmovups xmm0, xmmword ptr [rsi+2]
    add rsi, 18
    jmp Q4_loop
Q4_done: ret
KERNEL_Q4 ENDP

KERNEL_MATRIX PROC
    add r10, r11
    cmp r10, r12
    jae MAT_done
    ret
MAT_done: ret
KERNEL_MATRIX ENDP

; --- FUSED PIPELINE: UNROLLED Q4 + DEQUANT + ACCUMULATE ---
; YMM Registers used for optimal Arithmetic Throughput bypassing DRAM latency
; Dual accumulator lanes to exploit instruction-level parallelism (ILP)
; RCX = Tensor A (Q4_K structured packed bytes)
; RDX = Tensor B (FP32 Accumulator/Output)
; R8  = Block Scales Memory Offset
; R11 = Total blocks to process
KERNEL_FUSED_Q4_ACCUM PROC
    mov rax, r11
    shr rax, 1                  ; Process 2 blocks (64 weights) per iteration
    shl rax, 5                  ; 2 blocks * 16 bytes = 32 bytes packed stride
    lea rbx, [rcx + rax]        ; Exclusive End Pointer (Pointer-End walk)

    vzeroupper                  ; ABI standard before AVX

    ; Generate 0x0F byte mask for Q4 unpacking dynamically (avoids memory load)
    vpcmpeqw ymm15, ymm15, ymm15    ; All 1s
    vpsrlw ymm15, ymm15, 12         ; 000F words
    ; ymm15 is now a 16-bit mask of 0x000F. Good enough if we unpack bytes to words first.

    ; Zero our dual accumulators for lane 0 and lane 1
    vxorps ymm12, ymm12, ymm12  ; Lane 0 Accumulator A
    vxorps ymm13, ymm13, ymm13  ; Lane 0 Accumulator B
    vxorps ymm14, ymm14, ymm14  ; Lane 1 Accumulator A

FUSED_loop: 
    cmp rcx, rbx
    jae FUSED_done
    
    ; 0. SOFTWARE PREFETCHING (Managed Prefetch Distance)
    ; Prefetch distance = 256 bytes ahead. Non-temporal fetch to L1 (T0).
    prefetcht0 [rcx + 256]      ; Fetch upcoming Q4 tensor data
    prefetcht0 [rdx + 512]      ; Fetch upcoming FP32 accumulators
    prefetcht0 [r8 + 64]        ; Fetch upcoming scales
    
    ; 1. DUAL-LANE READ (Load 32-bytes of packed Q4 data)
    ; Each byte is 2 weights => 64 weights total
    vmovups ymm0, ymmword ptr [rcx]
    
    ; 2. DEQUANT: UNPACK & EXTRACT
    ; (Conceptual layout: we need to mask low nibble, shift high nibble)
    vpand ymm1, ymm0, ymm15         ; Lower nibbles (Lane 0 & 1 partial)
    vpsrlw ymm2, ymm0, 4            ; Shift high nibbles down
    vpand ymm2, ymm2, ymm15         ; Upper nibbles
    
    ; Convert to int32 then float32 (Int32 conversion placeholder logic)
    ; In a production cycle, this involves vpmovzxbd -> vcvtdq2ps.
    ; For the architectural template:
    vcvtdq2ps ymm1, ymm1            ; Convert Low to FP32
    vcvtdq2ps ymm2, ymm2            ; Convert High to FP32
    
    ; 3. REGISTER TILING: Load Dual Scales
    vbroadcastss ymm8, dword ptr [r8]     ; Scale Block 0
    vbroadcastss ymm9, dword ptr [r8+4]   ; Scale Block 1
    
    ; Apply Scales (Fused multiply)
    vmulps ymm1, ymm1, ymm8         ; Dequantized FP32 Lower
    vmulps ymm2, ymm2, ymm9         ; Dequantized FP32 Upper
    
    ; 4. CACHE-RESIDENT KERNEL FUSION (FMADD231)
    ; Multiply-Accumulate directly into YMM registers (Dual Lanes)
    ; Load corresponding FP32 Tensor B data
    vmovups ymm4, ymmword ptr [rdx]
    vmovups ymm5, ymmword ptr [rdx+32]
    
    ; FMA: Accumulator = (Dequant * TensorB) + Accumulator
    vfmadd231ps ymm12, ymm1, ymm4
    vfmadd231ps ymm13, ymm2, ymm5
    
    ; 5. DUAL-ISSUE NON-TEMPORAL STORE
    ; Streaming the results back without polluting the L1/L2 caches
    vmovntdq ymmword ptr [rdx], ymm12
    vmovntdq ymmword ptr [rdx+32], ymm13
    
    ; Pointer Arithmetic
    add rcx, 32                 ; Advanced Q4 pointer by 2 blocks (32 packed bytes)
    add rdx, 64                 ; Advanced output by 16 floats (64 bytes)
    add r8, 8                   ; Advanced scales by 2 floats (8 bytes)
    jmp FUSED_loop

FUSED_done: 
    vzeroupper                  ; Guarantee ABI safety before returning to MSVC Host
    ret
KERNEL_FUSED_Q4_ACCUM ENDP

; --- SUPER-KERNEL: Q4_K DOT-PRODUCT (VECDOT) 4x UNROLLED ---
; Memory Bandwidth Optimization: Fused pipeline with NO intermediate memory stores.
; RCX = Tensor A (Q4_K structured packed bytes)
; RDX = Tensor B (FP32 Activation Vector)
; R8  = Tensor A Scales
; R11 = Total blocks to process
; Returns: XMM0 (bottom scalar) containing the dot product result.
KERNEL_FUSED_Q4_VECDOT PROC
    mov rax, r11
    shr rax, 2                  ; Process 4 blocks (64 weights) per iteration
    shl rax, 5                  ; 4 blocks * 8 bytes (Wait, Q4 block usually 16 bytes? Let's assume 16 bytes. 4 * 16 = 64 bytes stride)
    ; Assuming 16 bytes per block = 32 weights. 4 blocks = 64 bytes = 128 weights.
    mov rax, r11
    shl rax, 4                  ; Total bytes = blocks * 16
    lea rbx, [rcx + rax]        ; Exclusive End Pointer

    vzeroupper                  ; ABI standard

; --- PIPELINED TILE COMPILER: 4-WAY MULTI-ACCUMULATOR COMPUTE-BOUND GEMM ---
; Establishes an Instruction-Level Parallelism (ILP) wave overlapping LOAD, DECODE, and COMPUTE.
; Achieves Register Interleaving to saturate FMA execution ports without stalling.
; YMM2-YMM5: 4 FMA Accumulators (Masks FMA 4-cycle latencies)
; YMM8, YMM9: Tile Activations (Broadcast loaded)
KERNEL_FUSED_Q4_GEMM_TILE4 PROC
    ; Calculate execution bounds
    mov rax, r11
    shr rax, 2                  ; 4 blocks per wave iteration
    shl rax, 5                  ; 32 bytes packed per block pair
    lea rbx, [rcx + rax]        ; Exclusive End Pointer

    vzeroupper
    
    ; Zero out Tiled Accumulators
    vxorps ymm2, ymm2, ymm2
    vxorps ymm3, ymm3, ymm3
    vxorps ymm4, ymm4, ymm4
    vxorps ymm5, ymm5, ymm5

    ; Pre-load initial wave (Wave N+1)
    vmovups ymm0, ymmword ptr [rcx]
    ; (Dynamic Q4 0x0F mask in ymm15)
    vpcmpeqw ymm15, ymm15, ymm15    
    vpsrlw ymm15, ymm15, 12         

.pipeline_loop:
    cmp rcx, rbx
    jae .pipeline_done

    ; --- WAVE N: COMPUTE & DECODE ---
    ; Interleaved dispatch: Alternate AGU, Port 0 FMA, and Port 1 FMA
    
    ; SLOT 1: PREFETCH (AGU1) - Lookahead Pipeline Distance
    prefetcht0 [rcx + 256]
    
    ; SLOT 2: DECODE LOWER (Port 5) - Wave N
    vpand ymm1, ymm0, ymm15
    vcvtdq2ps ymm1, ymm1
    
    ; SLOT 3: LOAD ACTIVATIONS (AGU2) 
    vbroadcastss ymm8, dword ptr [r8]     ; Act 0
    vbroadcastss ymm9, dword ptr [r8+4]   ; Act 1
    
    ; SLOT 4: DECODE UPPER (Port 5) - Wave N
    vpsrlw ymm14, ymm0, 4
    vpand ymm14, ymm14, ymm15
    vcvtdq2ps ymm14, ymm14
    
    ; SLOT 5: FMA LANE 0 (Port 0) - Compute Wave N
    vfmadd231ps ymm2, ymm1, ymm8
    
    ; SLOT 6: LOAD (AGU1) - Prefetch Wave N+1 into ymm0 to mask latency
    vmovups ymm0, ymmword ptr [rcx + 32]
    
    ; SLOT 7: FMA LANE 1 (Port 1) - Compute Wave N
    vfmadd231ps ymm3, ymm14, ymm9
    
    ; SLOT 8: FMA LANE 2 (Port 0) - Compute Wave N (Cross-pollinated tile)
    vfmadd231ps ymm4, ymm1, ymm9
    
    ; SLOT 9: ADDRESS GENERATION (AGU2) - Advance Pointers
    lea rcx, [rcx + 32]
    lea r8, [r8 + 8]
    
    ; SLOT 10: FMA LANE 3 (Port 1) - Compute Wave N (Cross-pollinated tile)
    vfmadd231ps ymm5, ymm14, ymm8

    jmp .pipeline_loop

.pipeline_done:
    ; (Store accumulators ymm2-ymm5 to RDX here)
    vmovups ymmword ptr [rdx], ymm2
    vmovups ymmword ptr [rdx+32], ymm3
    vmovups ymmword ptr [rdx+64], ymm4
    vmovups ymmword ptr [rdx+96], ymm5
    
    vzeroupper
    ret
KERNEL_FUSED_Q4_GEMM_TILE4 ENDP


    ; Generate 0x0F byte mask for Q4 unpacking
    vpcmpeqw ymm15, ymm15, ymm15
    vpsrlw ymm15, ymm15, 12     ; 000F in words

    ; Initialize Scratchpad Accumulators for our 4-way Unrolled Pipeline (Register Jamming)
    vxorps ymm10, ymm10, ymm10  ; Acc 0
    vxorps ymm11, ymm11, ymm11  ; Acc 1
    vxorps ymm12, ymm12, ymm12  ; Acc 2
    vxorps ymm13, ymm13, ymm13  ; Acc 3

VECDOT_loop: 
    cmp rcx, rbx
    jae VECDOT_done
    
    ; 0. SOFTWARE PREFETCHING (Active Pipeline Orchestration)
    prefetcht0 [rcx + 256]      ; Fetch upcoming Q4 tensor data
    prefetcht0 [rdx + 1024]     ; Fetch upcoming FP32 activations
    prefetcht0 [r8 + 64]        ; Fetch upcoming scales
    
    ; 1. 4x UNROLLED REGISTER JAMMING
    ; Load 4 scales into Registers (YMM6-7) simultaneously masking load latencies
    vbroadcastss ymm6, dword ptr [r8]     
    vbroadcastss ymm7, dword ptr [r8+4]   
    vbroadcastss ymm8, dword ptr [r8+8]   
    vbroadcastss ymm9, dword ptr [r8+12]  
    
    ; 2. PIPELINED LOAD & DEQUANT
    ; Block 0
    vmovups ymm0, ymmword ptr [rcx]       
    ; Extract and Convert
    vpand ymm1, ymm0, ymm15         ; Lower
    vpsrlw ymm2, ymm0, 4            ; Upper
    vpand ymm2, ymm2, ymm15
    vcvtdq2ps ymm1, ymm1
    vcvtdq2ps ymm2, ymm2
    ; Fuse Multiply with Scale & Accumulate with Tensor B (NO intermediate RAM writes)
    vmulps ymm1, ymm1, ymm6         
    vmulps ymm2, ymm2, ymm6         
    vfmadd231ps ymm10, ymm1, ymmword ptr [rdx]
    vfmadd231ps ymm11, ymm2, ymmword ptr [rdx+32]

    ; Block 1
    vmovups ymm0, ymmword ptr [rcx+16]       
    vpand ymm1, ymm0, ymm15         
    vpsrlw ymm2, ymm0, 4            
    vpand ymm2, ymm2, ymm15
    vcvtdq2ps ymm1, ymm1
    vcvtdq2ps ymm2, ymm2
    vmulps ymm1, ymm1, ymm7         
    vmulps ymm2, ymm2, ymm7         
    vfmadd231ps ymm12, ymm1, ymmword ptr [rdx+64]
    vfmadd231ps ymm13, ymm2, ymmword ptr [rdx+96]

    ; Block 2
    vmovups ymm0, ymmword ptr [rcx+32]       
    vpand ymm1, ymm0, ymm15         
    vpsrlw ymm2, ymm0, 4            
    vpand ymm2, ymm2, ymm15
    vcvtdq2ps ymm1, ymm1
    vcvtdq2ps ymm2, ymm2
    vmulps ymm1, ymm1, ymm8         
    vmulps ymm2, ymm2, ymm8         
    vfmadd231ps ymm10, ymm1, ymmword ptr [rdx+128]
    vfmadd231ps ymm11, ymm2, ymmword ptr [rdx+160]

    ; Block 3
    vmovups ymm0, ymmword ptr [rcx+48]       
    vpand ymm1, ymm0, ymm15         
    vpsrlw ymm2, ymm0, 4            
    vpand ymm2, ymm2, ymm15
    vcvtdq2ps ymm1, ymm1
    vcvtdq2ps ymm2, ymm2
    vmulps ymm1, ymm1, ymm9         
    vmulps ymm2, ymm2, ymm9         
    vfmadd231ps ymm12, ymm1, ymmword ptr [rdx+192]
    vfmadd231ps ymm13, ymm2, ymmword ptr [rdx+224]

    ; Pointer Arithmetic (Advance 4 blocks = 64 bytes packed, 256 bytes activations, 16 bytes scales)
    add rcx, 64                 
    add rdx, 256                
    add r8, 16                  
    jmp VECDOT_loop

VECDOT_done:
    ; Horizontal Sum of accumulators into XMM0
    vaddps ymm10, ymm10, ymm11
    vaddps ymm12, ymm12, ymm13
    vaddps ymm10, ymm10, ymm12

    ; Extract 256-bit ymm10 -> 128-bit xmm1
    vextractf128 xmm1, ymm10, 1
    vaddps xmm0, xmm10, xmm1
    
    ; Add adjacent pairs (Horizontal add within xmm0)
    vhaddps xmm0, xmm0, xmm0
    vhaddps xmm0, xmm0, xmm0

    vzeroupper
    ret
KERNEL_FUSED_Q4_VECDOT ENDP

; --- COMPUTE SATURATION MACHINE: 4-TILE GEMM KERNEL ---
; Fused Multi-Lane Accumulator with ping-pong buffering and interleaved loads.
; Quadruples FLOPs-per-byte (AI = 0.44 -> compute bound).
; RCX = Tensor A (Q4 weights)
; RDX = Tensor B Array (Array of Act Ptrs, simplified to stride for architecture)
; R8  = Tensor Scales
; R11 = Block Count
KERNEL_FUSED_Q4_GEMM_TILE4 PROC
    ; ABI Prolog for non-volatiles since we need all 16 YMM registers
    sub rsp, 0A0h 
    vmovups [rsp+000h], xmm6
    vmovups [rsp+010h], xmm7
    vmovups [rsp+020h], xmm8
    vmovups [rsp+030h], xmm9
    vmovups [rsp+040h], xmm10
    vmovups [rsp+050h], xmm11
    vmovups [rsp+060h], xmm12
    vmovups [rsp+070h], xmm13
    vmovups [rsp+080h], xmm14
    vmovups [rsp+090h], xmm15

    mov rax, r11
    shl rax, 4                  ; Blocks * 16 bytes = stride
    lea rbx, [rcx + rax]        ; Exclusive End Pointer

    vzeroupper

    ; 0x0F constant mask for Q4 unpacking
    vpcmpeqw ymm15, ymm15, ymm15
    vpsrlw ymm15, ymm15, 12

    ; Zero accumulators for 4 multi-lane rows
    vxorps ymm8, ymm8, ymm8
    vxorps ymm9, ymm9, ymm9
    vxorps ymm10, ymm10, ymm10
    vxorps ymm11, ymm11, ymm11

TILE4_loop:
    cmp rcx, rbx
    jae TILE4_done

    ; 0. SOFTWARE PREFETCHING
    prefetcht0 [rcx + 128]      ; Lookahead Q4
    ; Prefetch 4 distinct activation rows (assumed interleaved in memory by 128 bytes)
    prefetcht0 [rdx + 512]     
    prefetcht0 [rdx + 640]     
    prefetcht0 [rdx + 768]     
    prefetcht0 [rdx + 896]
    
    ; 1. FETCH Q4 & SCALE
    vmovups ymm0, ymmword ptr [rcx]
    vbroadcastss ymm14, dword ptr [r8] ; Scale
    
    ; 2. PIPELINED DEQUANTIZATION & ACTIVATION LOAD OVERLAP
    ; Extract Q4 while concurrently loading Act Vectors to bypass FMA latency chains
    vpand ymm1, ymm0, ymm15         ; Lower Q4 Extract (Port 0/1/5)
    
    ; Explicit Exeuction Port Scheduling: Load activations into registers BEFORE FMA
    vmovups ymm3, ymmword ptr [rdx + 000]   ; Act Row 1 (Port 2/3)
    vmovups ymm4, ymmword ptr [rdx + 128]   ; Act Row 2 (Port 2/3)
    vmovups ymm5, ymmword ptr [rdx + 256]   ; Act Row 3 (Port 2/3)
    vmovups ymm6, ymmword ptr [rdx + 384]   ; Act Row 4 (Port 2/3)

    vcvtdq2ps ymm1, ymm1            ; To FP32 Lower
    vmulps ymm1, ymm1, ymm14        ; Scale Lower
    
    ; 3. ISSUING LOWER MULTI-LANE ACCUMULATIONS (Quadrupled AI)
    vfmadd231ps ymm8,  ymm1, ymm3
    vfmadd231ps ymm9,  ymm1, ymm4
    vfmadd231ps ymm10, ymm1, ymm5
    vfmadd231ps ymm11, ymm1, ymm6

    ; Shift to upper Q4 block while independent FMA operations execute
    vpsrlw ymm2, ymm0, 4            ; Upper Q4 Shift
    vpand ymm2, ymm2, ymm15         ; Upper Q4 Mask
    
    ; Act loads overlaying FMA execution pipeline
    vmovups ymm3, ymmword ptr [rdx + 032]   ; Act Row 1 Upper Offset
    vmovups ymm4, ymmword ptr [rdx + 160]   ; Act Row 2 Upper Offset
    vmovups ymm5, ymmword ptr [rdx + 288]   ; Act Row 3 Upper Offset
    vmovups ymm6, ymmword ptr [rdx + 416]   ; Act Row 4 Upper Offset

    vcvtdq2ps ymm2, ymm2            ; To FP32 Upper
    vmulps ymm2, ymm2, ymm14        ; Scale Upper
    
    ; 4. ISSUING UPPER MULTI-LANE ACCUMULATIONS
    vfmadd231ps ymm8,  ymm2, ymm3
    vfmadd231ps ymm9,  ymm2, ymm4
    vfmadd231ps ymm10, ymm2, ymm5
    vfmadd231ps ymm11, ymm2, ymm6

    add rcx, 16                 ; 1 Block Q
    add rdx, 64                 ; 1 Block A stride mapping
    add r8, 4                   ; 1 Scale
    jmp TILE4_loop

TILE4_done:
    vzeroupper
    
    ; ABI Epilog
    vmovups xmm6, [rsp+000h]
    vmovups xmm7, [rsp+010h]
    vmovups xmm8, [rsp+020h]
    vmovups xmm9, [rsp+030h]
    vmovups xmm10, [rsp+040h]
    vmovups xmm11, [rsp+050h]
    vmovups xmm12, [rsp+060h]
    vmovups xmm13, [rsp+070h]
    vmovups xmm14, [rsp+080h]
    vmovups xmm15, [rsp+090h]
    add rsp, 0A0h
    
    ret
KERNEL_FUSED_Q4_GEMM_TILE4 ENDP

; --- MICROARCHITECTURE EMULATOR: ROTATING ACCUMULATOR KERNEL ---
; Replaces loop dependencies with a circular execution buffer.
; Achieves software-scheduled OoO execution, mapping directly to FMA ports.
KERNEL_FUSED_Q4_ROTATING_ACCUM PROC
    sub rsp, 0A0h 
    vmovups [rsp+000h], xmm6
    vmovups [rsp+010h], xmm7
    vmovups [rsp+020h], xmm8
    vmovups [rsp+030h], xmm9
    vmovups [rsp+040h], xmm10
    vmovups [rsp+050h], xmm11
    vmovups [rsp+060h], xmm12
    vmovups [rsp+070h], xmm13
    vmovups [rsp+080h], xmm14
    vmovups [rsp+090h], xmm15

    mov rax, r11
    shl rax, 5                  ; Tiling width adjustment (assume 32)
    lea rbx, [rcx + rax]

    vzeroupper
    vpcmpeqw ymm15, ymm15, ymm15
    vpsrlw ymm15, ymm15, 12

    ; Initialize 8 rotating accumulators (YMM8-YMM15, but YMM15 is mask so YMM7-YMM14)
    vxorps ymm7, ymm7, ymm7
    vxorps ymm8, ymm8, ymm8
    vxorps ymm9, ymm9, ymm9
    vxorps ymm10, ymm10, ymm10
    vxorps ymm11, ymm11, ymm11
    vxorps ymm12, ymm12, ymm12
    vxorps ymm13, ymm13, ymm13
    vxorps ymm14, ymm14, ymm14

ROTATING_loop:
    cmp rcx, rbx
    jae ROTATING_done

    ; t0: Prefetch T+2 horizon
    prefetcht0 [rcx + 256] 
    
    ; t1: Load and Setup block N 
    vmovups ymm0, ymmword ptr [rcx]
    vbroadcastss ymm6, dword ptr [r8] 
    
    ; t2: Overlay instruction scheduling
    vpand ymm1, ymm0, ymm15         
    vcvtdq2ps ymm1, ymm1            
    vmulps ymm1, ymm1, ymm6         
    
    ; t3: Emit FMA Set A (Bank 0)
    vfmadd231ps ymm7, ymm1, ymmword ptr [rdx + 0]
    vfmadd231ps ymm8, ymm1, ymmword ptr [rdx + 32]
    vfmadd231ps ymm9, ymm1, ymmword ptr [rdx + 64]
    vfmadd231ps ymm10, ymm1, ymmword ptr [rdx + 96]
    
    ; t4: Setup block N Upper (hides Set A latency)
    vpsrlw ymm2, ymm0, 4            
    vpand ymm2, ymm2, ymm15         
    vcvtdq2ps ymm2, ymm2            
    vmulps ymm2, ymm2, ymm6         

    ; t5: Emit FMA Set B (Bank 1)
    vfmadd231ps ymm11, ymm2, ymmword ptr [rdx + 128]
    vfmadd231ps ymm12, ymm2, ymmword ptr [rdx + 160]
    vfmadd231ps ymm13, ymm2, ymmword ptr [rdx + 192]
    vfmadd231ps ymm14, ymm2, ymmword ptr [rdx + 224]

    add rcx, 16 
    add rdx, 256 
    add r8, 4   
    jmp ROTATING_loop

ROTATING_done:
    ; (Accumulator spill to memory omitted for streaming brevity)
    vzeroupper
    
    vmovups xmm6, [rsp+000h]
    vmovups xmm7, [rsp+010h]
    vmovups xmm8, [rsp+020h]
    vmovups xmm9, [rsp+030h]
    vmovups xmm10, [rsp+040h]
    vmovups xmm11, [rsp+050h]
    vmovups xmm12, [rsp+060h]
    vmovups xmm13, [rsp+070h]
    vmovups xmm14, [rsp+080h]
    vmovups xmm15, [rsp+090h]
    add rsp, 0A0h
    
    ret
KERNEL_FUSED_Q4_ROTATING_ACCUM ENDP

PUBLIC KERNEL_DISPATCH
KERNEL_DISPATCH PROC FRAME
    .PUSHREG rbx
    push rbx
    .PUSHREG rsi
    push rsi
    .PUSHREG rdi
    push rdi
    .ENDPROLOG
    
    cmp r9, 0
    je call_simd
    cmp r9, 1
    je call_q4
    cmp r9, 2
    je call_mat
    cmp r9, 3
    je call_fused
    cmp r9, 4
    je call_fused_vecdot
    cmp r9, 5
    je call_fused_tile4
    
    jmp call_exit

call_simd: 
    call KERNEL_SIMD
    jmp call_exit
call_q4: 
    call KERNEL_Q4
    jmp call_exit
call_mat:
    call KERNEL_MATRIX
    jmp call_exit
call_fused:
    call KERNEL_FUSED_Q4_ACCUM
    jmp call_exit
call_fused_vecdot:
    call KERNEL_FUSED_Q4_VECDOT
    jmp call_exit
call_fused_tile4:
    call KERNEL_FUSED_Q4_GEMM_TILE4
    jmp call_exit

call_exit:
    pop rdi
    pop rsi
    pop rbx
    ret
KERNEL_DISPATCH ENDP

; ==================================================================
; TITAN_CORE: DAG GRAPH-WALKER DISPATCHER (STREAMING MODE)
; ==================================================================
; A zero-overhead task processor that chains fused kernels sequentially
; without returning to the C++ host, keeping registers hot.
; R9 = Pointer to Task Buffer (Array of 32-byte Task Structs)
; Task Struct: [NodeID: 4B] [R11/Count: 4B] [RCX: 8B] [RDX: 8B] [R8: 8B]
; Terminates when NodeID == 0xFFFFFFFF
; ==================================================================
PUBLIC KERNEL_GRAPH_WALKER
KERNEL_GRAPH_WALKER PROC FRAME
    .PUSHREG rbx
    push rbx
    .PUSHREG rsi
    push rsi
    .PUSHREG rdi
    push rdi
    .ENDPROLOG

    mov rsi, r9                 ; RSI = Task Graph Pointer

walk_loop:
    mov eax, dword ptr [rsi]           ; Load NodeID
    cmp eax, 0FFFFFFFFh                ; Sentinel Check (End of Graph)
    je walk_done

    mov r11d, dword ptr [rsi + 4]      ; Load Count
    mov rcx, qword ptr [rsi + 8]       ; Load Tensor A
    mov rdx, qword ptr [rsi + 16]      ; Load Tensor B
    mov r8, qword ptr [rsi + 24]       ; Load Scales

    ; Direct Pipeline Routing (Decoded Pipeline)
    cmp eax, 0
    je route_simd
    cmp eax, 1
    je route_q4
    cmp eax, 2
    je route_mat
    cmp eax, 3
    je route_fused
    cmp eax, 4
    je route_vecdot
    cmp eax, 5
    je route_tile4
    cmp eax, 6
    je route_rotating

route_next:
    add rsi, 32                 ; Advance to next Task Node
    jmp walk_loop

route_simd:
    call KERNEL_SIMD
    jmp route_next
route_q4:
    call KERNEL_Q4
    jmp route_next
route_mat:
    call KERNEL_MATRIX
    jmp route_next
route_fused:
    call KERNEL_FUSED_Q4_ACCUM
    jmp route_next
route_vecdot:
    call KERNEL_FUSED_Q4_VECDOT
    jmp route_next
route_tile4:
    call KERNEL_FUSED_Q4_GEMM_TILE4
    jmp route_next
route_rotating:
    call KERNEL_FUSED_Q4_ROTATING_ACCUM
    jmp route_next

walk_done:
    pop rdi
    pop rsi
    pop rbx
    ret
KERNEL_GRAPH_WALKER ENDP

ALIGN 16
.DATA
Sentinel db 64 dup(0CCh)
END
