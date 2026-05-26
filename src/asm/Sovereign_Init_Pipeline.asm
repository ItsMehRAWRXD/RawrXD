; ==============================================================================
; Sovereign_Init_Pipeline.asm
; Logic: Monolithic Bootstrap for the Sovereign Engine
; Features: Pool Creation, Bridge Mapping, Seed Priming, and GIS Initialization
; ==============================================================================

INCLUDE Sovereign_Common.inc

; ------------------------------------------------------------------------------
; EXTERNAL SYMBOLS
; ------------------------------------------------------------------------------
EXTERN RawrXD_Sched_Init          : PROC
EXTERN RawrXD_Ring_Init           : PROC
EXTERN InitializeEntropyEngine    : PROC
EXTERN InitializeGeoMapper        : PROC
EXTERN InitializeWorldNetwork     : PROC
EXTERN RawrXD_MXCSR_LockPerformance : PROC
EXTERN Sovereign_Audit_Init       : PROC
EXTERN SovInf_Init                : PROC
EXTERN SovInf_LoadWeights         : PROC
EXTERN Sovereign_Initialize_All_Systems : PROC

; ------------------------------------------------------------------------------
; SYMBOLS TO INITIALIZE
; ------------------------------------------------------------------------------
EXTERNDEF g_pGlobalRing              : QWORD ; Defined in Sovereign_Cyclic_Dispatch.asm

.DATA
    align 8
    g_RingCapacity      dq 1048576 ; 1MB Ring Buffer
    
    ; Goldilocks Priority Constants
    HIGH_PRIORITY_CLASS           EQU 00000080h
    THREAD_PRIORITY_TIME_CRITICAL EQU 15
    MASK_CORES_2_TO_N             EQU 0FFFFFFFCh ; Skip Core 0 (OS) and 1 (I/O)

    ; Miami, FL Anchor (Example)
    g_MiamiLat          real8 25.7617
    g_MiamiLon          real8 -80.1918

.CODE

; ------------------------------------------------------------------------------
; PROCEDURE: Sovereign_Engine_Bootstrap
; Logic: Performs absolute bare-metal initialization before loop entry.
; ------------------------------------------------------------------------------
Sovereign_Engine_Bootstrap PROC
    SOVEREIGN_PUSH_FRAME

    ; 1. Set Goldilocks Priority (HIGH_PRIORITY_CLASS)
    call [g_ApiTable.pGetCurrentProcess]
    mov rcx, rax               ; hProcess
    mov rdx, HIGH_PRIORITY_CLASS
    call [g_ApiTable.pSetPriorityClass]
    
    ; 2. Set Time-Critical Thread Priority
    call [g_ApiTable.pGetCurrentThread]
    mov rcx, rax               ; hThread
    mov rdx, THREAD_PRIORITY_TIME_CRITICAL
    call [g_ApiTable.pSetThreadPriority]

    ; 3. Core Pinning (Pin to Cores 2-N to avoid OS/Interrupt Jitter)
    call [g_ApiTable.pGetCurrentProcess]
    mov rcx, rax
    mov rdx, MASK_CORES_2_TO_N
    call [g_ApiTable.pSetProcessAffinityMask]
    
    ; 4. Initialize Deterministic FP State (FTZ+DAZ)
    call RawrXD_MXCSR_LockPerformance

    ; 5. Initialize Entropy/Dispatch/GIS via Bridge
    call Sovereign_Initialize_All_Systems
    
    ; 6. Initialize Scheduler (UMS Thread Pool)
    call RawrXD_Sched_Init
    
    ; 7. Allocate and Initialize Ring Bridge
    mov rcx, 0
    mov rdx, [g_RingCapacity]
    add rdx, 64 ; Header size
    mov r8, 3000h  ; MEM_COMMIT | MEM_RESERVE
    mov r9, 04h    ; PAGE_READWRITE
    call [g_ApiTable.pVirtualAlloc]
    test rax, rax
    jz @@Error
    
    mov [g_pGlobalRing], rax
    mov rcx, rax
    mov rdx, [g_RingCapacity]
    call RawrXD_Ring_Init
    
    ; 7. Initialize Geo-Mapper
    movsd xmm0, [g_MiamiLat]
    movsd xmm1, [g_MiamiLon]
    call InitializeGeoMapper
    
    ; 8. Initialize Network Array
    call InitializeWorldNetwork

    SOVEREIGN_POP_FRAME
    ret

@@Error:
    SOVEREIGN_POP_FRAME
    ret
Sovereign_Engine_Bootstrap ENDP

END

    ; 11. Load Default Model (Miami_Narrative_v1.gguf)
    lea rcx, g_DefaultModelPath
    call SovInf_LoadWeights
    ; We don't fail-hard on model load for the demo bootstrap
    
    mov rax, 1 ; Success
    jmp @@Done

@@Error:
    xor rax, rax

@@Done:
    add rsp, 48
    pop rbp
    ret
Sovereign_Engine_Bootstrap ENDP

.DATA
    align 8
    g_DefaultModelPath dw 'M','i','a','m','i','_','N','a','r','r','a','t','i','v','e','_','v','1','.','g','g','u','f', 0


END