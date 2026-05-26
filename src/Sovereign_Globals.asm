; ==============================================================================
; Sovereign_Globals.asm - Global Data and Subsystem Initialization
; ==============================================================================

include Sovereign_Common.inc
include Sovereign_Registry.inc

.DATA
PUBLIC g_ApiTable
PUBLIC g_pGov
PUBLIC g_pTPS
PUBLIC g_HeapBase
PUBLIC g_HeapPtr
PUBLIC g_HeapLimit
PUBLIC g_SovereignHub
PUBLIC g_pGlobalRing
PUBLIC g_DispatchTable
PUBLIC g_DbgTocPIdx
PUBLIC g_DbgMallocRet
PUBLIC g_DbgLoaderR13
PUBLIC g_DbgPIdxFieldAddr
PUBLIC g_DbgPIdxReadback

g_ApiTable      SOVEREIGN_API_TABLE <>
g_pGov          DQ 0
g_pTPS          DQ 0
g_HeapBase      DQ 0
g_HeapPtr       DQ 0
g_HeapLimit     DQ 0
g_SovereignHub  SovereignHub <>
g_pGlobalRing   DQ 0
g_DispatchTable DISPATCH_TABLE <>
g_DbgMallocRet     DQ 0
g_DbgLoaderR13     DQ 0
g_DbgPIdxFieldAddr DQ 0
g_DbgPIdxReadback  DQ 0
g_DbgTocPIdx       DQ 0

.CODE

; ----------------------------------------------------------------------------
; Ring_Push_Atomic
; ----------------------------------------------------------------------------
PUBLIC Ring_Push_Atomic
Ring_Push_Atomic PROC
    ; RCX = Ring Base, RDX = Value
    ; For now, a simple non-atomic push or stub to allow link
    ret
Ring_Push_Atomic ENDP

; ----------------------------------------------------------------------------
; Sovereign_Bootstrap_Core
; Ready the engine for sovereign execution.
; ----------------------------------------------------------------------------
PUBLIC Sovereign_Bootstrap_Core
Sovereign_Bootstrap_Core PROC
    push rbx
    ; In a real deployment, this would verify hardware security (TPM/SGX)
    ; or establish the encrypted transport lane.
    ; For now, we simply verify we have the minimal ISA (AVX-512)
    mov eax, 7
    xor ecx, ecx
    cpuid
    test ebx, 00010000h ; AVX-512 foundation
    jz @@Incompatible
    pop rbx
    mov rax, 1
    ret
@@Incompatible:
    pop rbx
    xor rax, rax
    ret
Sovereign_Bootstrap_Core ENDP

; ----------------------------------------------------------------------------
; Sovereign_SIMD_Scanner_Masked
; RCX = Base, RDX = Size, R8 = Offset
; ----------------------------------------------------------------------------
EXTERN Sovereign_AVX512_Tail_Scan : PROC

PUBLIC Sovereign_SIMD_Scanner_Masked
Sovereign_SIMD_Scanner_Masked PROC
    ; Minimal wrapper to orchestrate the scanner
    ; RCX = Pointer to data, RDX = Length
    push rbp
    mov rbp, rsp
    sub rsp, 32

    ; Pre-load signature for scanner (e.g. 0x55 0xAA)
    mov rax, 0AA55h
    vpbroadcastb zmm1, eax
    
    ; Logic: Scan in 64-byte blocks, then call Tail_Scan
@@ScanLoop:
    cmp rdx, 64
    jl @@Tail
    
    ; Full 64-byte scan
    vmovdqu8 zmm0, zmmword ptr [rcx]
    vpcmpub k1, zmm0, zmm1, 0
    kmovq rax, k1
    test rax, rax
    jnz @@MatchFound
    
    add rcx, 64
    sub rdx, 64
    jmp @@ScanLoop

@@Tail:
    test rdx, rdx
    jz @@Done
    mov r8, rcx
    mov rcx, rdx
    call Sovereign_AVX512_Tail_Scan
    jmp @@Done

@@MatchFound:
    ; Match logic here (simplified for smoke test)
    tzcnt rax, rax
    add rax, rcx
    ; In a real engine, we'd log this address or trigger an event.

@@Done:
    add rsp, 32
    pop rbp
    ret
Sovereign_SIMD_Scanner_Masked ENDP

END