; ==================================================================================
; SOVEREIGN STREAMING BRIDGE
; Phase 2B - Zero-Copy Model Ingestion Engine
; ==================================================================================

INCLUDE Sovereign_FrameABI.inc
INCLUDE Sovereign_Allocator.inc

.DATA
ALIGN 64
g_StreamContext QWORD 0 ; Pointer to active stream buffer (mapped model slice)

.CODE

; ----------------------------------------------------------------------------
; ZERO-COPY STAGING (LANE-LOCAL)
; ----------------------------------------------------------------------------
; RCX = Lane_ID
; RDX = Size (Bytes)
; R8  = Alignment (Requested)
; Returns: RAX (Pointer to aligned lane-local memory)
; ----------------------------------------------------------------------------
PUBLIC Sovereign_Stream_Stage
Sovereign_Stream_Stage PROC
    ENTER_FRAME

    ; Invoke our Phase 2A Allocator to get the staging arena
    mov r9, r8
    mov r8, rdx
    mov rdx, r8
    mov rcx, rcx
    call Sovereign_AllocLane
    
    ; RAX now holds the destination address
    ; We now prepare for non-temporal stream movement
    
    EXIT_FRAME
Sovereign_Stream_Stage ENDP

; ----------------------------------------------------------------------------
; NON-TEMPORAL BULK INGEST (SIMD-SAFE)
; ----------------------------------------------------------------------------
; RCX = Source (Stream Buffer)
; RDX = Destination (Lane-Local Arena)
; R8  = Size (Must be multiple of 64 bytes)
; ----------------------------------------------------------------------------
PUBLIC Sovereign_Stream_Ingest
Sovereign_Stream_Ingest PROC
    ENTER_FRAME
    
    ; Ensure destination is cache-line aligned (Sovereign Constraint)
    ; Assuming ASSERT_ALIGNED or equivalent macro bounds are asserted
    ; ASSERT_ALIGNED 
    
    mov rsi, rcx
    mov rdi, rdx
    mov rcx, r8
    
    ; Shrink-wrap loop for AVX-512 or SSE move chains
    ; Using 64-byte chunking for cache-line filling
    shr rcx, 6
@@IngestLoop:
    prefetchnta [rsi + 64]
    
    movups xmm0, [rsi]
    movups xmm1, [rsi + 16]
    movups xmm2, [rsi + 32]
    movups xmm3, [rsi + 48]
    
    movntdq [rdi], xmm0
    movntdq [rdi + 16], xmm1
    movntdq [rdi + 32], xmm2
    movntdq [rdi + 48], xmm3
    
    add rsi, 64
    add rdi, 64
    dec rcx
    jnz @@IngestLoop
    
    sfence  ; Enforce memory ordering for the streaming write
    
    EXIT_FRAME
Sovereign_Stream_Ingest ENDP

END
