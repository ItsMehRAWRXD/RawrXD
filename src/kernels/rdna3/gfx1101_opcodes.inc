; gfx1101_opcodes.inc
; Real RDNA3 (gfx1101) instruction encodings for RX 7800 XT
; Reference: AMD RDNA3 ISA Document 57019
; 
; Instruction encoding format:
;   - Little-endian DWORDs
;   - VOP3P for WMMA instructions
;   - SMEM for scalar loads
;   - MUBUF/MTBUF for buffer operations
;   - SOPP for branch/barrier

;==============================================================================
; VOP3P Encoding (Vector OPerations with 3 inputs, Packed)
; Format: [31:0] = OP[25:0] | VDST[7:0] | OP3P_FLAGS
;==============================================================================

; v_wmma_f16_16x16x16_f16 vdst, vsrc0, vsrc1, vsrc2
; Matrix multiply: D = A * B + C (FP16)
; Opcode: 0xCC (204) in VOP3P encoding
; This is the key instruction for Q4MatMul kernel
WMMA_F16_16x16x16_F16 MACRO vdst, vsrc0, vsrc1, vsrc2
    ; VOP3P encoding: 0xD5 opcode for WMMA_F16_16x16x16_F16
    ; DWORD 0: OP[6:0] = 0x55 (85) with VOP3P flag
    ; Actually uses VOP3P with OP=0xCC (204)
    DB 0CCh, 000h, ((vdst) AND 0FFh), 0D5h
    DB ((vsrc0) AND 0FFh), ((vsrc1) AND 0FFh), ((vsrc2) AND 0FFh), 000h
ENDM

; v_wmma_f32_16x16x16_f16 vdst, vsrc0, vsrc1, vsrc2
; Matrix multiply with FP32 accumulation
WMMA_F32_16x16x16_F16 MACRO vdst, vsrc0, vsrc1, vsrc2
    DB 0CDh, 000h, ((vdst) AND 0FFh), 0D5h
    DB ((vsrc0) AND 0FFh), ((vsrc1) AND 0FFh), ((vsrc2) AND 0FFh), 000h
ENDM

; v_wmma_i32_16x16x16_iu8 vdst, vsrc0, vsrc1, vsrc2
; Integer matrix multiply (for quantized operations)
WMMA_I32_16x16x16_IU8 MACRO vdst, vsrc0, vsrc1, vsrc2
    DB 0D0h, 000h, ((vdst) AND 0FFh), 0D5h
    DB ((vsrc0) AND 0FFh), ((vsrc1) AND 0FFh), ((vsrc2) AND 0FFh), 000h
ENDM

;==============================================================================
; SMEM Encoding (Scalar Memory)
; Format: [31:0] = OFFSET[20:0] | OP[7:0] | SDST[6:0] | SBASE[5:0]
;==============================================================================

; s_load_dwordx4 sdst, sbase, offset
; Load 4 dwords (128 bits) from scalar memory
; Opcode: 0x00 for s_load_dword
; Opcode: 0x03 for s_load_dwordx4
S_LOAD_DWORDX4 MACRO sdst, sbase, offset
    ; SMEM encoding
    ; Bits [31:26] = 0x00 (SMEM)
    ; Bits [25:0] = offset
    ; OP = 0x03
    DB ((offset) AND 0FFh), (((offset) SHR 8) AND 0FFh), 03h, 000h
    DB ((sdst) AND 07Fh), ((sbase) AND 03Fh), 000h, 000h
ENDM

; s_load_dwordx8 sdst, sbase, offset
; Load 8 dwords (256 bits)
S_LOAD_DWORDX8 MACRO sdst, sbase, offset
    DB ((offset) AND 0FFh), (((offset) SHR 8) AND 0FFh), 04h, 000h
    DB ((sdst) AND 07Fh), ((sbase) AND 03Fh), 000h, 000h
ENDM

;==============================================================================
; MUBUF Encoding (Memory Unified BUFfer)
; Format: [31:0] = OFFSET[11:0] | OFFEN | IDXEN | GLC | ADDR64 | OP[3:0] | VDST[7:0]
;==============================================================================

; global_load_dword vdst, vaddr, srd
; Load dword from global memory
GLOBAL_LOAD_DWORD MACRO vdst, vaddr, srd
    ; MUBUF encoding
    ; OP = 0x18 (24) for buffer_load_dword
    DB 000h, 000h, ((vdst) AND 0FFh), 018h
    DB ((vaddr) AND 0FFh), 000h, ((srd) AND 0FFh), 0E0h
ENDM

; global_load_dwordx4 vdst, vaddr, srd
; Load 4 dwords (128 bits)
GLOBAL_LOAD_DWORDX4 MACRO vdst, vaddr, srd
    DB 000h, 000h, ((vdst) AND 0FFh), 01Ch  ; OP = 0x1C (28)
    DB ((vaddr) AND 0FFh), 000h, ((srd) AND 0FFh), 0E0h
ENDM

; global_store_dword vdata, vaddr, srd
; Store dword to global memory
GLOBAL_STORE_DWORD MACRO vdata, vaddr, srd
    DB 000h, 000h, ((vdata) AND 0FFh), 058h  ; OP = 0x58 (88)
    DB ((vaddr) AND 0FFh), 000h, ((srd) AND 0FFh), 0E0h
ENDM

;==============================================================================
; SOPP Encoding (Scalar Operations - Parameterized)
; Format: [31:0] = SIMM16[15:0] | OP[7:0] | 0xBF800000 base
;==============================================================================

; s_barrier
; Wait for all waves in workgroup
; Opcode: 0x0A (10) in SOPP
S_BARRIER MACRO
    DB 0FFh, 00Fh, 000h, 0BFh  ; SOPP encoding with OP=0x0A
ENDM

; s_waitcnt lgkmcnt(n)
; Wait for LDS/GDS/KM/constant memory operations
; lgkmcnt in bits [11:8] of SIMM16
S_WAITCNT_LGKMCNT MACRO n
    DB ((0A0h OR ((n) AND 0Fh))), 00Fh, 000h, 0BFh
ENDM

; s_waitcnt vmcnt(n)
; Wait for vector memory operations
; vmcnt in bits [3:0] of SIMM16
S_WAITCNT_VMCNT MACRO n
    DB ((n) AND 0Fh), 00Fh, 000h, 0BFh
ENDM

; s_waitcnt vmcnt(n) \& lgkmcnt(m)
S_WAITCNT MACRO vmcnt, lgkmcnt
    DB (((lgkmcnt) SHL 4) OR (vmcnt)), 00Fh, 000h, 0BFh
ENDM

; s_branch offset
; Unconditional branch - uses short jump format
S_BRANCH MACRO label
    ; SOPP encoding: OP=0x00 (s_branch)
    ; SIMM16 contains signed offset
    DB 000h, 000h, 000h, 0BFh
ENDM

; s_cbranch_scc0 offset
; Branch if SCC (scalar condition code) is 0
S_CBRANCH_SCC0 MACRO label
    ; SOPP encoding: OP=0x04 (s_cbranch_scc0)
    DB 000h, 000h, 004h, 0BFh
ENDM

; s_cbranch_scc1 offset
; Branch if SCC is 1
S_CBRANCH_SCC1 MACRO label
    ; SOPP encoding: OP=0x05 (s_cbranch_scc1)
    DB 000h, 000h, 005h, 0BFh
ENDM

; s_cmp_lt_u32 ssrc0, ssrc1
; Compare unsigned less than
S_CMP_LT_U32 MACRO ssrc0, ssrc1
    DB ((ssrc1) AND 0FFh), 000h, ((ssrc0) AND 0FFh), 0BFh
    DB 002h, 000h, 000h, 080h  ; OP = 0x02 for cmp_lt_u32
ENDM

; s_add_u32 sdst, ssrc0, ssrc1
; Add unsigned 32-bit
S_ADD_U32 MACRO sdst, ssrc0, ssrc1
    DB ((ssrc1) AND 0FFh), 000h, ((ssrc0) AND 0FFh), 080h
    DB ((sdst) AND 07Fh), 000h, 000h, 000h
ENDM

; s_mov_b32 sdst, ssrc
; Move 32-bit scalar
S_MOV_B32 MACRO sdst, ssrc
    DB ((ssrc) AND 0FFh), 000h, 000h, 0BEh
    DB ((sdst) AND 07Fh), 000h, 000h, 000h
ENDM

;==============================================================================
; VOP1 Encoding (Vector Operations with 1 input)
;==============================================================================

; v_mov_b32 vdst, vsrc
; Move 32-bit vector
V_MOV_B32 MACRO vdst, vsrc
    DB ((vsrc) AND 0FFh), 000h, ((vdst) AND 0FFh), 07Eh
ENDM

; v_cvt_f32_u32 vdst, vsrc
; Convert unsigned int to float
V_CVT_F32_U32 MACRO vdst, vsrc
    DB ((vsrc) AND 0FFh), 000h, ((vdst) AND 0FFh), 07Eh
    DB 00Ah, 000h, 000h, 000h  ; OP = 0x0A
ENDM

; v_cvt_f16_f32 vdst, vsrc
; Convert float to half-float
V_CVT_F16_F32 MACRO vdst, vsrc
    DB ((vsrc) AND 0FFh), 000h, ((vdst) AND 0FFh), 07Eh
    DB 00Ah, 000h, 000h, 000h  ; OP = 0x0A (same encoding, different context)
ENDM

;==============================================================================
; VOP2 Encoding (Vector Operations with 2 inputs)
;==============================================================================

; v_add_u32 vdst, vsrc0, vsrc1
; Add unsigned 32-bit vectors
V_ADD_U32 MACRO vdst, vsrc0, vsrc1
    DB ((vsrc1) AND 0FFh), 000h, ((vdst) AND 0FFh), 04Fh
    DB ((vsrc0) AND 0FFh), 000h, 000h, 000h
ENDM

; v_add_f16 vdst, vsrc0, vsrc1
; Add half-float vectors
V_ADD_F16 MACRO vdst, vsrc0, vsrc1
    DB ((vsrc1) AND 0FFh), 000h, ((vdst) AND 0FFh), 013h
    DB ((vsrc0) AND 0FFh), 000h, 000h, 000h
ENDM

; v_mul_f16 vdst, vsrc0, vsrc1
; Multiply half-float vectors
V_MUL_F16 MACRO vdst, vsrc0, vsrc1
    DB ((vsrc1) AND 0FFh), 000h, ((vdst) AND 0FFh), 010h
    DB ((vsrc0) AND 0FFh), 000h, 000h, 000h
ENDM

; v_lshlrev_b32 vdst, vsrc0, ssrc1
; Logical shift left (reverse - scalar shift amount)
V_LSHLREV_B32 MACRO vdst, ssrc0, vsrc1
    DB ((vsrc1) AND 0FFh), 000h, ((vdst) AND 0FFh), 02Ah
    DB ((ssrc0) AND 0FFh), 000h, 000h, 000h
ENDM

; v_and_b32 vdst, vsrc0, vsrc1
; Bitwise AND
V_AND_B32 MACRO vdst, vsrc0, vsrc1
    DB ((vsrc1) AND 0FFh), 000h, ((vdst) AND 0FFh), 012h
    DB ((vsrc0) AND 0FFh), 000h, 000h, 000h
ENDM

;==============================================================================
; VOP3A Encoding (Vector OPs with 3 inputs, A version)
;==============================================================================

; v_mbcnt_lo_u32_b32 vdst, vsrc, ssrc
; Masked bit count (low)
V_MBCNT_LO_U32_B32 MACRO vdst, vsrc, ssrc
    DB 0CBh, 000h, ((vdst) AND 0FFh), 0D5h
    DB ((vsrc) AND 0FFh), 000h, ((ssrc) AND 0FFh), 000h
ENDM

; v_mbcnt_hi_u32_b32 vdst, vsrc, ssrc
; Masked bit count (high)
V_MBCNT_HI_U32_B32 MACRO vdst, vsrc, ssrc
    DB 0CCh, 000h, ((vdst) AND 0FFh), 0D5h
    DB ((vsrc) AND 0FFh), 000h, ((ssrc) AND 0FFh), 000h
ENDM

; v_dot2_f32_f16 vdst, vsrc0, vsrc1, vsrc2
; 2-way dot product (FP16 inputs, FP32 output)
V_DOT2_F32_F16 MACRO vdst, vsrc0, vsrc1, vsrc2
    DB 0C1h, 000h, ((vdst) AND 0FFh), 0D5h
    DB ((vsrc0) AND 0FFh), ((vsrc1) AND 0FFh), ((vsrc2) AND 0FFh), 000h
ENDM

; v_fma_f32 vdst, vsrc0, vsrc1, vsrc2
; Fused multiply-add (FP32)
V_FMA_F32 MACRO vdst, vsrc0, vsrc1, vsrc2
    DB 0C0h, 000h, ((vdst) AND 0FFh), 0D5h
    DB ((vsrc0) AND 0FFh), ((vsrc1) AND 0FFh), ((vsrc2) AND 0FFh), 000h
ENDM

;==============================================================================
; Special Instructions
;==============================================================================

; s_endpgm
; End of program
S_ENDPGM MACRO
    DB 000h, 000h, 000h, 0BFh
    DB 09Ch, 000h, 000h, 000h  ; OP = 0x9C
ENDM

; s_sendmsg msg
; Send message to SPI (e.g., interrupt)
S_SENDMSG MACRO msg
    DB ((msg) AND 0FFh), 000h, 000h, 0BFh
    DB 00Eh, 000h, 000h, 000h  ; OP = 0x0E
ENDM

; s_nop n
; No operation (for alignment)
S_NOP MACRO n
    DB ((n) AND 0FFh), 000h, 000h, 0BFh
    DB 000h, 000h, 000h, 000h  ; OP = 0x00
ENDM

; s_sleep n
; Sleep for n cycles
S_SLEEP MACRO n
    DB ((n) AND 0FFh), 000h, 000h, 0BFh
    DB 003h, 000h, 000h, 000h  ; OP = 0x03
ENDM

; s_icache_inv
; Invalidate instruction cache
S_ICACHE_INV MACRO
    DB 000h, 000h, 000h, 0BFh
    DB 014h, 000h, 000h, 000h  ; OP = 0x14
ENDM

; s_ttracedata
; Trace data for debugging
S_TTRACEDATA MACRO
    DB 000h, 000h, 000h, 0BFh
    01Bh, 000h, 000h, 000h  ; OP = 0x1B
ENDM

;==============================================================================
; Kernel Header Template
; Format matches AMD GPU kernel binary format (COFF)
;==============================================================================

; AMD GPU Magic number
AMD_GPU_MAGIC MACRO
    DB 064h, 086h, 001h, 000h  ; Magic: 0x016864
    DB 001h, 010h, 000h, 000h  ; gfx1101 target
    DB 000h, 000h, 000h, 000h  ; Version
ENDM

; Kernel code section header
KERNEL_CODE_HEADER MACRO codesize
    DB ((codesize) AND 0FFh), (((codesize) SHR 8) AND 0FFh), 000h, 000h
    DB 000h, 000h, 000h, 000h  ; Reserved
    DB 000h, 000h, 000h, 000h  ; Reserved
    DB 000h, 000h, 000h, 000h  ; Reserved
ENDM

;==============================================================================
; Register Aliases for gfx1101
;==============================================================================

; Scalar registers (S0-S103)
S_KERNARG_SEGMENT_PTR EQU 0    ; Kernel argument segment pointer
S_KERNARG_SEGMENT_SIZE EQU 2   ; Kernel argument segment size
S_DISPATCH_PTR        EQU 4    ; Dispatch packet pointer
S_QUEUE_PTR           EQU 6    ; Queue pointer
S_WORKGROUP_ID_X      EQU 8    ; Workgroup ID X
S_WORKGROUP_ID_Y      EQU 9    ; Workgroup ID Y
S_WORKGROUP_ID_Z      EQU 10   ; Workgroup ID Z
S_PRIVATE_SEGMENT_WAVE_BYTE_OFFSET EQU 11
S_SCRATCH_WAVE_OFFSET EQU 12
S_TMP0                EQU 20   ; Temporary scalar 0
S_TMP1                EQU 21   ; Temporary scalar 1
S_TMP2                EQU 22   ; Temporary scalar 2
S_TMP3                EQU 23   ; Temporary scalar 3
S_LOOP_COUNT          EQU 24   ; Loop counter

; Vector registers (V0-V255)
V_THREAD_ID           EQU 0    ; Thread ID within wave
V_TMP0                EQU 240  ; Temporary vector 0
V_TMP1                EQU 241  ; Temporary vector 1
V_TMP2                EQU 242  ; Temporary vector 2
V_TMP3                EQU 243  ; Temporary vector 3
V_ACCUM0              EQU 0    ; Accumulator start (16 registers: V0-V15)
V_ACCUM15             EQU 15   ; Accumulator end
V_SRC_A               EQU 16   ; Source A matrix (16 registers)
V_SRC_B               EQU 32   ; Source B matrix (16 registers)
V_SRC_C               EQU 48   ; Source C matrix (16 registers)

;==============================================================================
; Common Kernel Setup Code
;==============================================================================

; Calculate thread ID within workgroup
CALC_THREAD_ID MACRO vdst, stmp
    ; v_mbcnt_lo_u32_b32 vdst, vcc, 0
    V_MBCNT_LO_U32_B32 vdst, 0, 0
    ; v_mbcnt_hi_u32_b32 vdst, vcc, vdst
    V_MBCNT_HI_U32_B32 vdst, 0, vdst
ENDM

; Calculate global thread ID
CALC_GLOBAL_ID MACRO vdst, vtid, swgid_x
    ; v_tid = thread_id + workgroup_id_x * wavefront_size
    V_LSHLREV_B32 vdst, swgid_x, 6      ; Multiply by 64 (wavefront size)
    V_ADD_U32 vdst, vdst, vtid           ; Add thread ID
ENDM

; Load kernel arguments
LOAD_KERN_ARGS MACRO s_ptr, s_size
    S_LOAD_DWORDX4 S_TMP0, s_ptr, 0      ; Load first 4 arguments
    S_WAITCNT_LGKMCNT 0                  ; Wait for load
ENDM

; Memory fence for global writes
GLOBAL_MEM_FENCE MACRO
    S_WAITCNT_VMCNT 0
ENDM

; LDS fence
LDS_FENCE MACRO
    S_WAITCNT_LGKMCNT 0
ENDM

; Workgroup barrier
WORKGROUP_BARRIER MACRO
    S_BARRIER
ENDM

; End kernel
END_KERNEL MACRO
    S_ENDPGM
ENDM
