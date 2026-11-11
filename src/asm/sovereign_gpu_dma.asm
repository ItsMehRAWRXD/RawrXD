; ============================================================================
; Sovereign GPU DMA Bridge — High-Speed VRAM Write (MASM x64)
; ============================================================================
; Target: AMD RX 7800 XT (RDNA3) via PCIe BAR
; Method: REP MOVSQ with SFENCE for maximum throughput
; Alignment: 64-byte source, 256-byte destination (RDNA3 cache line)
;
; Entry Points:
;   Sovereign_DMA_Write      - General purpose DMA (64-byte aligned)
;   Sovereign_DMA_Write256   - 256-byte optimized (RDNA3 cache line)
;   Sovereign_DMA_Flush      - Cache fence after writes
;   Sovereign_DMA_Bulk       - Large transfer with prefetch
;
; Performance Target: 20k TPS requires ~50GB/s memory bandwidth
; This path bypasses all driver overhead and writes directly to VRAM BAR.
; ============================================================================

; x64 MASM - No .MODEL directive needed for x64
OPTION CASEMAP:NONE

; ============================================================================
; External Dependencies
; ============================================================================

EXTERN GetLastError:PROC
EXTERN SetLastError:PROC

; ============================================================================
; Public Exports
; ============================================================================

PUBLIC Sovereign_DMA_Write
PUBLIC Sovereign_DMA_Write256
PUBLIC Sovereign_DMA_Flush
PUBLIC Sovereign_DMA_Bulk
PUBLIC Sovereign_DMA_Prefetch

; ============================================================================
; Constants
; ============================================================================

RDNA3_CACHE_LINE    EQU 256     ; RDNA3 cache line size
PCIe_PAGE_SIZE      EQU 4096    ; PCIe page size
PREFETCH_DISTANCE   EQU 4096    ; Prefetch ahead distance

; Status codes
GPU_OK              EQU 0
GPU_ERR_ALIGN_SRC   EQU -3
GPU_ERR_ALIGN_DST   EQU -4
GPU_ERR_SIZE        EQU -5

; ============================================================================
; .DATA Section — Initialized Data
; ============================================================================

.DATA

; Error message strings (for debugging)
g_szAlignSrcErr     BYTE "Sovereign DMA: Source not 64-byte aligned", 0
g_szAlignDstErr     BYTE "Sovereign DMA: Destination not 256-byte aligned", 0
g_szSizeErr         BYTE "Sovereign DMA: Size not 64-byte aligned", 0

; Performance counters (updated by each call)
g_qwTotalBytes      QWORD 0     ; Total bytes transferred
g_qwTotalCalls      QWORD 0     ; Total DMA calls
g_qwLastCycles      QWORD 0     ; Cycles for last transfer

; ============================================================================
; .CODE Section — Implementation
; ============================================================================

.CODE

; ----------------------------------------------------------------------------
; Sovereign_DMA_Write
;   High-speed DMA from host memory to GPU VRAM BAR
;
; Parameters (Windows x64 ABI):
;   RCX = Destination (GPU VRAM BAR virtual address, 256-byte aligned)
;   RDX = Source (Host memory, 64-byte aligned)
;   R8  = Size in bytes (must be multiple of 64)
;
; Returns:
;   RAX = Status code (GPU_OK or error)
;
; Clobbers: RAX, RCX, RDX, R8, R9, R10, R11, XMM0-XMM5
; ----------------------------------------------------------------------------

Sovereign_DMA_Write PROC FRAME
    ; Prologue
    push    rbp
    .pushreg rbp
    mov     rbp, rsp
    .setframe rbp, 0
    push    rdi
    .pushreg rdi
    push    rsi
    .pushreg rsi
    push    rbx
    .pushreg rbx
    push    r12
    .pushreg r12
    .endprolog

    ; Save parameters
    mov     rdi, rcx            ; RDI = Destination (GPU VRAM)
    mov     rsi, rdx            ; RSI = Source (Host)
    mov     rcx, r8             ; RCX = Size
    mov     r12, r8             ; R12 = Original size for stats

    ; Validate alignment
    test    rdi, 0FFh           ; Destination must be 256-byte aligned
    jnz     @@align_dst_err
    
    test    rsi, 3Fh            ; Source must be 64-byte aligned
    jnz     @@align_src_err
    
    test    rcx, 3Fh            ; Size must be 64-byte aligned
    jnz     @@size_err

    ; Check for zero size
    test    rcx, rcx
    jz      @@done

    ; Update call counter
    inc     qword ptr [g_qwTotalCalls]

    ; Get start timestamp (RDTSC)
    rdtscp                      ; EDX:EAX = timestamp, ECX = processor ID
    shl     rdx, 32
    or      rax, rdx
    push    rax                 ; Save start time on stack

    ; Prefetch source data into L2 cache
    mov     rbx, rsi            ; RBX = current prefetch position
    mov     rdx, rcx            ; RDX = remaining size
@@prefetch_loop:
    cmp     rdx, 4096
    jb      @@prefetch_done
    prefetcht0  [rbx + 4096]    ; Prefetch 4KB ahead
    add     rbx, 4096
    sub     rdx, 4096
    jmp     @@prefetch_loop
@@prefetch_done:

    ; Main copy loop using REP MOVSQ
    ; This is the fastest way to move large aligned blocks on x64
    cld                         ; Clear direction flag (forward)
    shr     rcx, 3              ; Convert bytes to QWORDs
    rep movsq                   ; Copy RCX QWORDs from [RSI] to [RDI]

    ; Memory fence to ensure writes complete before return
    sfence                      ; Serialize stores to VRAM

    ; Get end timestamp and calculate cycles
    rdtscp
    shl     rdx, 32
    or      rax, rdx
    pop     rbx                 ; RBX = start time
    sub     rax, rbx            ; RAX = elapsed cycles
    mov     [g_qwLastCycles], rax

    ; Update total bytes counter
    add     qword ptr [g_qwTotalBytes], r12

    ; Return success
    xor     eax, eax            ; RAX = GPU_OK
    jmp     @@done

@@align_src_err:
    mov     eax, GPU_ERR_ALIGN_SRC
    jmp     @@done

@@align_dst_err:
    mov     eax, GPU_ERR_ALIGN_DST
    jmp     @@done

@@size_err:
    mov     eax, GPU_ERR_SIZE

@@done:
    ; Epilogue
    pop     r12
    pop     rbx
    pop     rsi
    pop     rdi
    pop     rbp
    ret

Sovereign_DMA_Write ENDP

; ----------------------------------------------------------------------------
; Sovereign_DMA_Write256
;   Optimized 256-byte write (single RDNA3 cache line)
;
; Parameters:
;   RCX = Destination (256-byte aligned)
;   RDX = Source (64-byte aligned)
;
; Returns:
;   RAX = Status code
; ----------------------------------------------------------------------------

Sovereign_DMA_Write256 PROC FRAME
    push    rbp
    .pushreg rbp
    mov     rbp, rsp
    push    rdi
    .pushreg rdi
    push    rsi
    .pushreg rsi
    .endprolog

    mov     rdi, rcx            ; Destination
    mov     rsi, rdx            ; Source

    ; Validate alignment
    test    rdi, 0FFh
    jnz     @@align_err

    ; Load 256 bytes (4 x 64 bytes) using AVX-512 if available, else AVX2
    ; For maximum compatibility, use AVX2 (ymm registers)
    
    ; Load 4 x 256 bits = 128 bytes per pair
    vmovdqu ymm0, ymmword ptr [rsi]
    vmovdqu ymm1, ymmword ptr [rsi + 32]
    vmovdqu ymm2, ymmword ptr [rsi + 64]
    vmovdqu ymm3, ymmword ptr [rsi + 96]
    vmovdqu ymm4, ymmword ptr [rsi + 128]
    vmovdqu ymm5, ymmword ptr [rsi + 160]
    vmovdqu ymm6, ymmword ptr [rsi + 192]
    vmovdqu ymm7, ymmword ptr [rsi + 224]

    ; Non-temporal stores to VRAM (bypass cache, write-combining)
    vmovntdq ymmword ptr [rdi], ymm0
    vmovntdq ymmword ptr [rdi + 32], ymm1
    vmovntdq ymmword ptr [rdi + 64], ymm2
    vmovntdq ymmword ptr [rdi + 96], ymm3
    vmovntdq ymmword ptr [rdi + 128], ymm4
    vmovntdq ymmword ptr [rdi + 160], ymm5
    vmovntdq ymmword ptr [rdi + 192], ymm6
    vmovntdq ymmword ptr [rdi + 224], ymm7

    ; Fence to ensure completion
    sfence

    ; Clear AVX state
    vzeroupper

    xor     eax, eax            ; Success
    jmp     @@done

@@align_err:
    mov     eax, GPU_ERR_ALIGN_DST

@@done:
    pop     rsi
    pop     rdi
    pop     rbp
    ret

Sovereign_DMA_Write256 ENDP

; ----------------------------------------------------------------------------
; Sovereign_DMA_Flush
;   Cache fence after VRAM writes (RDNA3 specific)
;
; Parameters: None
; Returns: None
; ----------------------------------------------------------------------------

Sovereign_DMA_Flush PROC
    sfence                      ; Ensure all stores complete
    mfence                      ; Full memory fence (if needed)
    ret
Sovereign_DMA_Flush ENDP

; ----------------------------------------------------------------------------
; Sovereign_DMA_Bulk
;   Large transfer with automatic chunking and prefetch
;
; Parameters:
;   RCX = Destination
;   RDX = Source
;   R8  = Size in bytes
;   R9  = Chunk size (0 = auto, default 64KB)
;
; Returns:
;   RAX = Status code
; ----------------------------------------------------------------------------

Sovereign_DMA_Bulk PROC FRAME
    push    rbp
    .pushreg rbp
    mov     rbp, rsp
    push    rdi
    .pushreg rdi
    push    rsi
    .pushreg rsi
    push    rbx
    .pushreg rbx
    push    r12
    .pushreg r12
    push    r13
    .pushreg r13
    push    r14
    .pushreg r14
    .endprolog

    mov     rdi, rcx            ; Destination
    mov     rsi, rdx            ; Source
    mov     rbx, r8             ; RBX = Total size
    mov     r12, r9             ; R12 = Chunk size

    ; Default chunk size = 64KB
    test    r12, r12
    jnz     @@chunk_set
    mov     r12, 65536
@@chunk_set:

    ; Align chunk size to 64 bytes
    and     r12, -64

    ; Save original destination for return
    mov     r13, rdi
    mov     r14, rsi

@@chunk_loop:
    ; Determine chunk size
    mov     rcx, r12
    cmp     rbx, r12
    jae     @@do_chunk
    mov     rcx, rbx            ; Last chunk (smaller)

@@do_chunk:
    test    rcx, rcx
    jz      @@chunks_done

    ; Call Sovereign_DMA_Write for this chunk
    push    rbx
    push    r12
    push    r13
    push    r14
    
    mov     r8, rcx             ; Size
    mov     rdx, r14            ; Source
    mov     rcx, r13            ; Destination
    call    Sovereign_DMA_Write
    
    pop     r14
    pop     r13
    pop     r12
    pop     rbx

    ; Check result
    test    eax, eax
    jnz     @@error

    ; Advance pointers
    add     r13, r12
    add     r14, r12
    sub     rbx, r12
    jg      @@chunk_loop

@@chunks_done:
    xor     eax, eax            ; Success
    jmp     @@done

@@error:
    ; Error code already in EAX

@@done:
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    pop     rsi
    pop     rdi
    pop     rbp
    ret

Sovereign_DMA_Bulk ENDP

; ----------------------------------------------------------------------------
; Sovereign_DMA_Prefetch
;   Prefetch host memory into cache before DMA
;
; Parameters:
;   RCX = Host memory address
;   RDX = Size in bytes
; ----------------------------------------------------------------------------

Sovereign_DMA_Prefetch PROC FRAME
    push    rdi
    .pushreg rdi
    push    rsi
    .pushreg rsi
    .endprolog

    mov     rsi, rcx            ; Source
    mov     rdi, rdx            ; Size

@@loop:
    cmp     rdi, 4096
    jb      @@done
    prefetcht0 [rsi]
    add     rsi, 4096
    sub     rdi, 4096
    jmp     @@loop

@@done:
    pop     rsi
    pop     rdi
    ret

Sovereign_DMA_Prefetch ENDP

; ----------------------------------------------------------------------------
; Sovereign_DMA_GetStats
;   Get performance statistics
;
; Parameters:
;   RCX = Pointer to 3 QWORDs (total bytes, total calls, last cycles)
; ----------------------------------------------------------------------------

Sovereign_DMA_GetStats PROC FRAME
    push    rdi
    .pushreg rdi
    .endprolog

    mov     rdi, rcx
    mov     rax, qword ptr [g_qwTotalBytes]
    mov     qword ptr [rdi], rax
    mov     rax, qword ptr [g_qwTotalCalls]
    mov     qword ptr [rdi + 8], rax
    mov     rax, qword ptr [g_qwLastCycles]
    mov     qword ptr [rdi + 16], rax

    pop     rdi
    ret

Sovereign_DMA_GetStats ENDP

; ----------------------------------------------------------------------------
; Sovereign_DMA_ResetStats
;   Reset performance counters
; ----------------------------------------------------------------------------

Sovereign_DMA_ResetStats PROC
    mov     qword ptr [g_qwTotalBytes], 0
    mov     qword ptr [g_qwTotalCalls], 0
    mov     qword ptr [g_qwLastCycles], 0
    ret
Sovereign_DMA_ResetStats ENDP

; ============================================================================
; End of Code Section
; ============================================================================

END
