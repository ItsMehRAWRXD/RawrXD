; ==============================================================================
; SOVEREIGN CORE FABRIC SCHEDULER
; File: Sovereign_Fabric_Scheduler.asm
; Role: Multi-Stream, Zero-Copy, Thread-Pinned Execution Matrix
; Focus: 16-Way Independent Inference without Ring Buffers (Direct Physical)
; ==============================================================================

include Sovereign_Common.inc
include Sovereign_FrameABI.inc

; Constants mapping to the UI "Multi-Chat" / concurrent stream limits
MAX_STREAMS EQU 16

; Stream Execution States
STREAM_STATE_FREE        EQU 0
STREAM_STATE_INGESTING   EQU 1
STREAM_STATE_READY       EQU 2
STREAM_STATE_EXECUTING   EQU 3

; 64-byte aligned context per independent stream
STREAM_CONTEXT STRUCT
    State           QWORD ?
    Arena_Offset    QWORD ?   ; Fixed physical region (NO Ring Buffer)
    ShadowMap_Ptr   QWORD ?   ; Local DAG shadow state
    DAG_Head_Ptr    QWORD ?   ; Execution graph root
    DAG_Count       QWORD ?
    Reserved1       QWORD ?
    Reserved2       QWORD ?
    Reserved3       QWORD ?
STREAM_CONTEXT ENDS

.DATA
    ALIGN 64
    ; The Fabric Matrix: 16 Independent Streams
    g_Fabric_Matrix STREAM_CONTEXT MAX_STREAMS DUP(<0>)
    
    ; 16-Thread Physical Mask (0xFFFF) mapped to topology
    g_Fabric_ThreadMask QWORD 000000000000FFFFh

.CODE

EXTERN Sovereign_Registry_Lookup:PROC
EXTERN Sovereign_Shadow_Wait:PROC
EXTERN Sovereign_Shadow_Update:PROC

; ==============================================================================
; Sovereign_Fabric_Dispatch_Loop
; Role: The Multi-Stream Non-Blocking execution router for physical threads
; ==============================================================================
PUBLIC Sovereign_Fabric_Dispatch_Loop
Sovereign_Fabric_Dispatch_Loop PROC
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    ENTER_FRAME

@@FabricTick:
    ; Iterating over 16 streams
    mov rbx, 0
    lea rsi, [g_Fabric_Matrix]

@@StreamCheck:
    cmp rbx, MAX_STREAMS
    jae @@FabricTick ; Loop fabric infinitely (Hardware-clocked scheduler)

    ; Is Stream Ready for Execution?
    mov rax, [rsi + STREAM_CONTEXT.State]
    cmp rax, STREAM_STATE_READY
    jne @@NextStream

    ; Lock stream into Executing state
    mov rax, STREAM_STATE_EXECUTING
    lock xchg [rsi + STREAM_CONTEXT.State], rax
    cmp rax, STREAM_STATE_READY
    jne @@NextStream ; Race condition protection

    ; --- ENTER ZERO-COPY DAG EXECUTION (No Middle Man) ---
    mov r12, [rsi + STREAM_CONTEXT.DAG_Head_Ptr]
    mov r13, [rsi + STREAM_CONTEXT.DAG_Count]
    
@@NodeLoop:
    test r13, r13
    jz @@StreamComplete
    
    ; Note: Memory accesses here hit specific subsets of the Arena assigned to this stream
    ; Wait for DMA or upstream dependency to hit READY
    mov rcx, r12
    sub rcx, [rsi + STREAM_CONTEXT.DAG_Head_Ptr]
    shr rcx, 5 ; Node Index
    ; (Add Shadow Wait logic if required per stream, omitted for ultra-fast loop demo)

    ; Setup FMA Kernel Parameters
    ; Directly binding to your massive Kernel Library
    mov rcx, [r12 + 8] ; Input Hash/Ptr
    mov rdx, [r12 + 16] ; Output Hash/Ptr
    mov r8,  [r12 + 24] ; Size/Params
    
    ; Kernel Call (Your AVX-512 FMA)
    call [r12 + 0] ; KernelPtr

    ; Next node
    add r12, 32
    dec r13
    jmp @@NodeLoop

@@StreamComplete:
    ; Reset stream to FREE
    mov qword ptr [rsi + STREAM_CONTEXT.State], STREAM_STATE_FREE

@@NextStream:
    add rsi, TYPE STREAM_CONTEXT
    inc rbx
    jmp @@StreamCheck

    EXIT_FRAME
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret

Sovereign_Fabric_Dispatch_Loop ENDP

; ==============================================================================
; SOVEREIGN_BARRIER_SYNC
; RCX = Lane ID (0 = Master, 1-15 = Worker)
; R15 = Global Fabric Context (Pinned)
; ==============================================================================
PUBLIC Sovereign_Barrier_Sync
Sovereign_Barrier_Sync PROC
    ; 1. Check if Master (Lane 0)
    test rcx, rcx
    jz @Master_Sync

@Worker_Sync:
    ; A. Worker Check-in: Atomically increment Fence_State
    ; R15 + 60h is Fence_State
    lock inc dword ptr [r15 + 60h]

    ; B. Spin-Wait for Reset (Fence_State == 0)
@Worker_Wait:
    pause
    cmp dword ptr [r15 + 60h], 0
    jne @Worker_Wait
    ret

@Master_Sync:
    ; C. Master Wait: Spin until all 15 workers have checked in
    ; We wait for Fence_State to reach 15
@Master_Wait:
    pause
    cmp dword ptr [r15 + 60h], 15
    jl @Master_Wait
    
    ; D. Pulse Advance: Reset Fence_State to 0 to release all workers
    mov dword ptr [r15 + 60h], 0
    ret
Sovereign_Barrier_Sync ENDP

END
