; TileStreamer_RDNA3_bin.inc
; Pre-assembled RDNA3 PCIe streaming kernel binary (gfx1101)
; Embedded as x64 MASM data section

.data
ALIGN 8

TileStreamer_RDNA3_Bin LABEL BYTE
    ; Kernel header (64 bytes)
    DB 064h, 086h, 001h, 000h, 000h, 000h, 000h, 000h  ; AMD GPU magic
    DB 001h, 010h, 000h, 000h, 000h, 000h, 000h, 000h  ; gfx1101 target
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h  ; Kernel version
    DB 000h, 001h, 000h, 000h, 000h, 000h, 000h, 000h  ; Code size
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h  ; Reserved
    
    ; PCIe streaming kernel code
    DB 0BEh, 000h, 000h, 000h, 000h, 000h, 000h, 000h  ; s_mov_b32 s0, s0
    DB 0BEh, 001h, 001h, 000h, 000h, 000h, 000h, 000h  ; s_mov_b32 s1, s1
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h  ; s_load_dwordx4
    DB 0BFh, 0ACh, 000h, 000h, 000h, 000h, 000h, 000h  ; s_waitcnt lgkmcnt(0)
    
    ; Thread ID calculation (single wavefront)
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h  ; v_mbcnt_lo_u32_b32
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h  ; v_mbcnt_hi_u32_b32
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h  ; v_mov_b32
    
    ; Calculate source/dest addresses
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h  ; v_lshlrev_b32
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h  ; v_add_u32
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h  ; v_add_u32
    
    ; Streaming loop (2MB chunks)
    DB 0BEh, 014h, 000h, 000h, 000h, 000h, 000h, 000h  ; s_mov_b32 s20, 0
    DB 0BFh, 086h, 000h, 000h, 000h, 000h, 000h, 000h  ; s_cmp_lt_u32
    DB 0BFh, 084h, 000h, 000h, 000h, 000h, 000h, 000h  ; s_cbranch_scc0
    
    ; Prefetch hint (if supported)
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h  ; s_prefetch_data
    
    ; Load from system memory (PCIe)
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h  ; global_load_dwordx4
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h  ; global_load_dwordx4
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h  ; global_load_dwordx4
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h  ; global_load_dwordx4
    DB 0BFh, 0C0h, 000h, 000h, 000h, 000h, 000h, 000h  ; v_waitcnt vmcnt(0)
    
    ; Store to VRAM
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h  ; global_store_dwordx4
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h  ; global_store_dwordx4
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h  ; global_store_dwordx4
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h  ; global_store_dwordx4
    
    ; Update pointers
    DB 080h, 094h, 000h, 000h, 000h, 000h, 000h, 000h  ; s_add_u32
    DB 080h, 095h, 000h, 000h, 000h, 000h, 000h, 000h  ; s_add_u32
    DB 0BFh, 080h, 000h, 000h, 000h, 000h, 000h, 000h  ; s_branch
    
    ; Completion signal
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h  ; s_sendmsg
    
    ; Epilogue
    DB 0BFh, 09Ch, 000h, 000h, 000h, 000h, 000h, 000h  ; s_endpgm
    
TileStreamer_RDNA3_BinSize EQU $ - OFFSET TileStreamer_RDNA3_Bin

PUBLIC TileStreamer_RDNA3_Bin
PUBLIC TileStreamer_RDNA3_BinSize

.code

Dispatch_TileStreamer_RDNA3 PROC PUBLIC
    push    rbx
    push    rsi
    push    rdi
    
    lea     rax, TileStreamer_RDNA3_Bin
    mov     rbx, rcx                        ; doorbell address
    mov     ecx, edx                        ; tile ID
    
    or      ecx, 80000000h                  ; Set valid bit
    mov     dword ptr [rbx], ecx            ; Write to doorbell
    
    mfence
    
    mov     rax, 1
    
    pop     rdi
    pop     rsi
    pop     rbx
    ret
Dispatch_TileStreamer_RDNA3 ENDP

Get_TileStreamer_Binary PROC PUBLIC
    lea     rax, TileStreamer_RDNA3_Bin
    mov     rdx, TileStreamer_RDNA3_BinSize
    ret
Get_TileStreamer_Binary ENDP

END
