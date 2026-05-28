; ==================================================================================
; SOVEREIGN UNIVERSAL STREAMING ENGINE
; Architecture: Descriptor-Driven Materialization
; File: Sovereign_Stream.asm
; ==================================================================================

include Sovereign_Common.inc
include Sovereign_FrameABI.inc

EXTERN Sovereign_Alloc:PROC

; Universal Descriptor Definition
SOV_DESC STRUCT
    Hash        QWORD ? ; FNV-1a Key
    Offset      QWORD ? ; File/Stream Offset
    Size        QWORD ? ; Data Size
    Stride      QWORD ? ; Element Stride (for NCHW/NHWC support)
    Flags       QWORD ? ; Alignment/Prefetch settings
    DataPtr     QWORD ? ; Materialized Pointer
SOV_DESC ENDS

.DATA
    ALIGN 64
    g_RegistryBase  QWORD 0 ; Pointer to Descriptor Array
    g_RegistryCount QWORD 0 ; Max capacity
    g_MappedView    QWORD 0 ; Base address of the mapped stream

.CODE

; ===============================================================================
; Sovereign_Universal_Lookup
; RCX = Hash, RDX = OutDesc
; Returns RAX = 1 (Success) / 0 (Failure)
; ===============================================================================
PUBLIC Sovereign_Universal_Lookup
Sovereign_Universal_Lookup PROC
    mov r8, [g_RegistryBase]
    mov r9, [g_RegistryCount]
    test r9, r9
    jz @@Fail
@@Loop:
    cmp [r8 + SOV_DESC.Hash], rcx
    je @@Found
    add r8, TYPE SOV_DESC
    dec r9
    jnz @@Loop
@@Fail:
    xor rax, rax
    ret
@@Found:
    mov [rdx], r8
    mov rax, 1
    ret
Sovereign_Universal_Lookup ENDP

; ===============================================================================
; Sovereign_Materialize_Tensor
; RCX = Ptr to Descriptor
; Materializes raw stream into aligned Arena
; ===============================================================================
PUBLIC Sovereign_Materialize_Tensor
Sovereign_Materialize_Tensor PROC
    ENTER_FRAME
    push r12
    push r13
    push rsi
    push rdi
    
    mov r12, rcx                ; R12 = Descriptor Ptr
    
    ; Load source address (Base + Offset)
    mov rdx, [r12 + SOV_DESC.Offset]
    add rdx, [g_MappedView]
    
    ; Check Alignment (Required for FMA-Fusion -> 64-byte Cache boundaries)
    test rdx, 63
    jz @@Direct
    
    ; If not aligned, route through Allocator Arena (Fallback)
    mov r13, rdx                ; R13 = Unaligned Source Pointer
    mov rcx, [r12 + SOV_DESC.Size]
    call Sovereign_Alloc
    
    ; Prefetch source into L1/L2
    prefetcht0 [r13]
    
    ; Fast hardware-optimized block copy (ERMS translates rep movsb into 256/512 bit operations)
    mov rdi, rax                ; Dest = Allocated pointer
    mov rsi, r13                ; Source = Unaligned pointer
    mov rcx, [r12 + SOV_DESC.Size]
    rep movsb
    jmp @@Done

@@Direct:
    mov rax, rdx
@@Done:
    mov [r12 + SOV_DESC.DataPtr], rax
    
    pop rdi
    pop rsi
    pop r13
    pop r12
    EXIT_FRAME
    ret
Sovereign_Materialize_Tensor ENDP

; ===============================================================================
; Sovereign_Streamer_Init
; Universal Initialization 
; RCX = DescriptorArrayPtr, RDX = Count, R8 = MappedViewBase
; ===============================================================================
PUBLIC Sovereign_Streamer_Init
Sovereign_Streamer_Init PROC
    mov [g_RegistryBase], rcx
    mov [g_RegistryCount], rdx
    mov [g_MappedView], r8
    ret
Sovereign_Streamer_Init ENDP

END
