; TileStreamer_RDNA3.asm
; Async PCIe prefetch kernel for weight/ KV cache streaming
; Runs on async compute queue, overlaps with main kernels
; Workgroup: 64 threads (1 wavefront), 16KB LDS

; PCIe DMA constants
PCIE_CHUNK_SIZE   EQU 2097152      ; 2MB chunks
PCIE_MAX_INFLIGHT EQU 4            ; Max 4 concurrent transfers
VRAM_PAGE_SIZE    EQU 65536        ; 64KB GPU pages

; Kernel arguments
ARG_HOST_SRC      EQU 0            ; Source pointer (system RAM)
ARG_GPU_DST       EQU 8            ; Destination pointer (VRAM)
ARG_SIZE          EQU 16           ; Total bytes to transfer
ARG_CHUNK_CB      EQU 24           ; Completion callback pointer

; Status codes
STATUS_IDLE       EQU 0
STATUS_COPYING    EQU 1
STATUS_COMPLETE   EQU 2
STATUS_ERROR      EQU 3

.code

;==============================================================================
; TileStreamer_RDNA3
; Async PCIe copy engine for weight/KV cache streaming
;==============================================================================
TileStreamer_RDNA3 PROC PUBLIC
    ; Prologue - minimal, runs on async queue
    s_mov_b32       s0, s0                          ; Workgroup ID = stream ID
    v_mbcnt_lo_u32_b32 v0, -1, 0                    ; Thread ID (0-63)
    
    ; Load arguments
    s_load_dwordx4  s[4:7], s[0:1], ARG_HOST_SRC
    s_load_dword    s8, s[0:1], ARG_SIZE
    s_waitcnt       lgkmcnt(0)
    
    ; Calculate chunk assignment
    v_lshrrev_b32   v1, 5, v0                       ; Chunk index (thread / 32)
    v_and_b32       v2, v0, 31                    ; Position within chunk
    
    ; Main copy loop
    s_mov_b32       s20, 0                          ; Offset
    s_mov_b32       s21, STATUS_COPYING             ; Set status
    
COPY_LOOP:
    s_cmp_lt_u32    s20, s8                         ; Check if done
    s_cbranch_scc0  COPY_DONE
    
    ; Calculate source and dest addresses
    v_lshlrev_b32   v3, 6, v2                       ; Position * 64 bytes
    v_add_u32       v4, v3, s20                     ; + offset
    v_add_u32       v5, v4, s4                      ; + host base
    v_add_u32       v6, v4, s6                      ; + GPU base
    
    ; Load from system RAM (cached)
    global_load_dwordx4 v[8:11], v[5:6], off        ; 64 bytes
    v_waitcnt       vmcnt(0)
    
    ; Store to VRAM (write-combined)
    global_store_dwordx4 v[6:7], v[8:11], off
    
    ; Update offset
    v_add_u32       v3, v3, 64                      ; Next position
    s_add_u32       s20, s20, 64                    ; Global offset
    
    ; Check for chunk boundary
    v_and_b32       v4, s20, (PCIE_CHUNK_SIZE-1)
    s_cmp_eq_u32    v4, 0
    s_cbranch_scc0  COPY_LOOP
    
    ; Chunk complete - signal callback
    s_load_dword    s22, s[0:1], ARG_CHUNK_CB
    s_waitcnt       lgkmcnt(0)
    s_store_dword   s21, s[22:23], 0                 ; Write completion status
    
    s_branch        COPY_LOOP
    
COPY_DONE:
    ; Signal completion
    s_mov_b32       s21, STATUS_COMPLETE
    s_store_dword   s21, s[22:23], 0
    
    s_endpgm
TileStreamer_RDNA3 ENDP

;==============================================================================
; StreamScheduler_RDNA3
; Schedules tile streams based on compute queue occupancy
;==============================================================================
StreamScheduler_RDNA3 PROC
    ; Read GPU occupancy counters
    s_getreg_b32    s0, hwreg(HW_REG_SQ_WAVE_ACTIVE)
    s_getreg_b32    s1, hwreg(HW_REG_SQ_WAVE_RECOVERY)
    
    ; Calculate free capacity
    s_sub_u32       s2, 120, s0                     ; 120 max - active
    
    ; If >80% free, prefetch next tile
    s_cmp_gt_u32    s2, 96                          ; >80%?
    s_cbranch_scc1  TRIGGER_PREFETCH
    
    ret
    
TRIGGER_PREFETCH:
    ; Write doorbell to trigger TileStreamer
    s_store_dword   1, s[10:11], 0                  ; Signal doorbell
    ret
StreamScheduler_RDNA3 ENDP

END
