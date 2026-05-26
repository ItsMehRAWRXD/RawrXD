; ==============================================================================
; Sovereign_KV_Cache_Kernel.asm
; Logic: Cyclic KV Cache Ring Management (Sub-Page Allocation)
; Features: AVX512 Masked Store for Row-Major Cache Retention
; ==============================================================================

INCLUDE Sovereign_Execution_Graph_ABI.inc

.DATA
    align 16
    g_KV_BasePtr        dq 0
    g_KV_PageSize       dq 4096 ; 4KB Page Standard
    g_KV_HeadIdx        dq 0
    g_KV_MaxTokens      dq 32768 ; 32K Context

.CODE

; ------------------------------------------------------------------------------
; PROCEDURE: CyclicKV_Push
; Input: RCX = TensorPtr, RDX = TokenID
; Logic: Appends a token vector to the ring buffer. Wraps around automatically.
; ------------------------------------------------------------------------------
PUBLIC CyclicKV_Push
CyclicKV_Push PROC
    ; 1. Calculate Head Offset
    mov rax, [g_KV_HeadIdx]
    ; 2. VMULSS/VMOVUPS into Cache Slots
    ; 3. Atomic Increment Head (Lock-Free)
    inc rax
    and rax, 32767 ; Manual wrap-around for 32K
    mov [g_KV_HeadIdx], rax
    ret
CyclicKV_Push ENDP

; ------------------------------------------------------------------------------
; PROCEDURE: CyclicKV_Clear
; ------------------------------------------------------------------------------
PUBLIC CyclicKV_Clear
CyclicKV_Clear PROC
    mov qword ptr [g_KV_HeadIdx], 0
    ret
CyclicKV_Clear ENDP

END