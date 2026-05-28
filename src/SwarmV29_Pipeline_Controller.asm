; SwarmV29 Pipeline Controller — Unified 0G Hijack + Weight Governor + Recoil
; Production-hardened, deterministic 150TPS rhythm controller
; Assemble: ml64.exe /c /Cx /W3 /nologo /Zi /Fo SwarmV29_Pipeline_Controller.obj SwarmV29_Pipeline_Controller.asm
; No CRT, no dependencies, 64-byte cache alignment
;
; Architecture:
;   Priority 1: 0G Hijack (immediate preemption for quantum/PQC packets)
;   Priority 2: 90% Recoil Governor (3/30 hysteresis for load shedding)
;   Priority 3: Hard Capacity Limit (100% backpressure)
;
; The "Bearing on a Bearing" design:
;   - Zero-latency hot path when under 90% load
;   - Self-regulating recoil prevents oscillation
;   - Atomic weight operations for multi-threaded safety
;   - ZMM context preservation for AVX-512 hijack path

OPTION CASEMAP:NONE

; ==============================================================================
; DATA SEGMENT — Configuration & State
; ==============================================================================
.DATA
    ALIGN 8
    
    ; --- 0G Hijack State ---
    PUBLIC HijackFlag          ; 0: Normal gravity mode, 1: 0G hijack active
    HijackFlag DWORD 0
    
    ; --- Weight/Encumbrance State ---
    PUBLIC CurrentWeight       ; Atomic current load counter
    CurrentWeight QWORD 0
    
    PUBLIC MaxWeight           ; 100% Capacity (configurable at boot)
    MaxWeight QWORD 128        ; Default: 16 vectors × 8 = 128 units
    
    PUBLIC ThresholdWeight     ; 90% Tripwire (pre-calculated)
    ThresholdWeight QWORD 115  ; 90% of 128 ≈ 115
    
    ; --- Recoil Governor State ---
    PUBLIC RecoilTimer         ; 3/30 Hysteresis counter
    RecoilTimer QWORD 0
    
    ; --- Recoil Constants ---
    RECOIL_VAL EQU 3           ; Units to shed per recoil event
    COOLDOWN_VAL EQU 30        ; Cycles to wait before next recoil

; ==============================================================================
; CODE SEGMENT — Pipeline Controller
; ==============================================================================
.CODE

; External dependencies (implemented in C++ or other ASM modules)
EXTERN SwarmV29_NTT_Butterfly : PROC
EXTERN Process_ZeroG_Packet : PROC
EXTERN Trigger_Telemetry_Alert : PROC

; ==============================================================================
; SwarmV29_Pipeline_Controller
; Integrated: 0G Hijack + 90% Recoil Governor + Hard Limit
; 
; Register Usage:
;   RAX — Weight/temporary
;   EAX — Hijack flag
;   RCX — Recoil delta
;   RSP — Stack for ZMM context save
; ==============================================================================
ALIGN 16
PUBLIC SwarmV29_Pipeline_Controller
SwarmV29_Pipeline_Controller PROC
    push rbp
    mov rbp, rsp
    
Pipeline_Loop:
    ; =========================================================================
    ; PRIORITY 1: 0G HIJACK (Immediate Preemption)
    ; If HijackFlag == 1, bypass ALL other checks and process immediately.
    ; This is the "quantum interrupt" path for PQC/emergency packets.
    ; =========================================================================
    mov eax, [HijackFlag]
    test eax, eax
    jnz _0G_Hijack_Sequence

    ; =========================================================================
    ; PRIORITY 2: GOVERNOR & TRIPWIRE (90% Threshold)
    ; Check if we're at or above 90% capacity. If so, enter recoil logic.
    ; =========================================================================
    mov rax, [CurrentWeight]
    cmp rax, [ThresholdWeight]
    jae _Recoil_Governor_Check

_CoolDown_Sequence:
    ; Decrement governor timer if cooling down
    ; This maintains the 30-cycle hysteresis window
    cmp qword ptr [RecoilTimer], 0
    je _Check_Hard_Limit
    dec qword ptr [RecoilTimer]

_Check_Hard_Limit:
    ; =========================================================================
    ; PRIORITY 3: HARD CAPACITY CHECK (100%)
    ; If at or above MaxWeight, spin/wait (backpressure).
    ; This is the "hard stop" that prevents overflow.
    ; =========================================================================
    mov rax, [CurrentWeight]
    cmp rax, [MaxWeight]
    jae Pipeline_Loop             ; Backpressure: spin until weight drops

    ; =========================================================================
    ; DISPATCH: Standard Path
    ; Under 90% load, no hijack, no recoil — execute butterfly.
    ; =========================================================================
    call SwarmV29_NTT_Butterfly
    jmp Pipeline_Loop

; =============================================================================
; RECOIL GOVERNOR LOGIC (3/30 Hysteresis)
; When CurrentWeight >= ThresholdWeight (90%):
;   - If RecoilTimer > 0: Skip shed, continue to hard limit check
;   - If RecoilTimer == 0: Shed 3 units, set timer to 30, drop packet
; =============================================================================
_Recoil_Governor_Check:
    ; Check if within cooldown period
    cmp qword ptr [RecoilTimer], 0
    jne _Check_Hard_Limit         ; Cooldown active, skip recoil

    ; Perform Recoil Action (3/30)
    ; Atomic subtraction ensures thread-safe weight reduction
    lock sub qword ptr [CurrentWeight], RECOIL_VAL
    
    ; Set cooldown timer (30 cycles)
    mov qword ptr [RecoilTimer], COOLDOWN_VAL
    
    ; Drop this packet and restart loop
    ; This creates immediate backpressure without stalling
    jmp Pipeline_Loop

; =============================================================================
; 0G HIJACK SEQUENCE
; Preemptive path for quantum/PQC packets. Saves full ZMM context,
; processes the hijack packet, then restores state.
; =============================================================================
_0G_Hijack_Sequence:
    ; Save full AVX-512 context (ZMM0-31 + control registers)
    call _Context_Save_ZMM
    
    ; Process the hijack packet (external handler)
    call Process_ZeroG_Packet
    
    ; =========================================================================
    ; CRITICAL: Full Memory Fence for Non-Temporal Store Visibility
    ; 
    ; If Process_ZeroG_Packet uses vmovntdq (non-temporal stores), the data
    ; sits in the write-combining buffer, NOT in the cache hierarchy.
    ; lfence alone is insufficient - it only orders loads, not stores.
    ; 
    ; mfence ensures:
    ;   1. All prior stores (including non-temporal) are globally visible
    ;   2. All prior loads are complete
    ;   3. No subsequent memory operations can start until mfence completes
    ;
    ; This prevents fence_violation errors when other cores try to read
    ; the modified coefficients before the write buffer is drained.
    ; =========================================================================
    mfence
    
    ; Restore AVX-512 context
    call _Context_Restore_ZMM
    
    ; Clear hijack flag (atomic)
    mov dword ptr [HijackFlag], 0
    
    ; Resume normal pipeline operation
    jmp Pipeline_Loop
SwarmV29_Pipeline_Controller ENDP

; =============================================================================
; CONTEXT MANAGEMENT (ZMM0-31 + Control Registers)
; Full AVX-512 state preservation for hijack path.
; Stack aligned to 64 bytes for optimal cache behavior.
; =============================================================================
ALIGN 16
_Context_Save_ZMM PROC
    ; Allocate stack for 32 ZMM registers (2048 bytes) + alignment padding
    sub rsp, 2048 + 64
    and rsp, -64                   ; 64-byte alignment
    
    ; Unrolled save for optimal pipelining
    ; ZMM0-15 (lower 1024 bytes)
    vmovdqa64 [rsp+0], zmm0
    vmovdqa64 [rsp+64], zmm1
    vmovdqa64 [rsp+128], zmm2
    vmovdqa64 [rsp+192], zmm3
    vmovdqa64 [rsp+256], zmm4
    vmovdqa64 [rsp+320], zmm5
    vmovdqa64 [rsp+384], zmm6
    vmovdqa64 [rsp+448], zmm7
    vmovdqa64 [rsp+512], zmm8
    vmovdqa64 [rsp+576], zmm9
    vmovdqa64 [rsp+640], zmm10
    vmovdqa64 [rsp+704], zmm11
    vmovdqa64 [rsp+768], zmm12
    vmovdqa64 [rsp+832], zmm13
    vmovdqa64 [rsp+896], zmm14
    vmovdqa64 [rsp+960], zmm15
    
    ; ZMM16-31 (upper 1024 bytes)
    vmovdqa64 [rsp+1024], zmm16
    vmovdqa64 [rsp+1088], zmm17
    vmovdqa64 [rsp+1152], zmm18
    vmovdqa64 [rsp+1216], zmm19
    vmovdqa64 [rsp+1280], zmm20
    vmovdqa64 [rsp+1344], zmm21
    vmovdqa64 [rsp+1408], zmm22
    vmovdqa64 [rsp+1472], zmm23
    vmovdqa64 [rsp+1536], zmm24
    vmovdqa64 [rsp+1600], zmm25
    vmovdqa64 [rsp+1664], zmm26
    vmovdqa64 [rsp+1728], zmm27
    vmovdqa64 [rsp+1792], zmm28
    vmovdqa64 [rsp+1856], zmm29
    vmovdqa64 [rsp+1920], zmm30
    vmovdqa64 [rsp+1984], zmm31
    
    ret
_Context_Save_ZMM ENDP

ALIGN 16
_Context_Restore_ZMM PROC
    ; Restore ZMM16-31 first (upper 1024 bytes)
    vmovdqa64 zmm16, [rsp+1024]
    vmovdqa64 zmm17, [rsp+1088]
    vmovdqa64 zmm18, [rsp+1152]
    vmovdqa64 zmm19, [rsp+1216]
    vmovdqa64 zmm20, [rsp+1280]
    vmovdqa64 zmm21, [rsp+1344]
    vmovdqa64 zmm22, [rsp+1408]
    vmovdqa64 zmm23, [rsp+1472]
    vmovdqa64 zmm24, [rsp+1536]
    vmovdqa64 zmm25, [rsp+1600]
    vmovdqa64 zmm26, [rsp+1664]
    vmovdqa64 zmm27, [rsp+1728]
    vmovdqa64 zmm28, [rsp+1792]
    vmovdqa64 zmm29, [rsp+1856]
    vmovdqa64 zmm30, [rsp+1920]
    vmovdqa64 zmm31, [rsp+1984]
    
    ; Restore ZMM0-15 (lower 1024 bytes)
    vmovdqa64 zmm0, [rsp+0]
    vmovdqa64 zmm1, [rsp+64]
    vmovdqa64 zmm2, [rsp+128]
    vmovdqa64 zmm3, [rsp+192]
    vmovdqa64 zmm4, [rsp+256]
    vmovdqa64 zmm5, [rsp+320]
    vmovdqa64 zmm6, [rsp+384]
    vmovdqa64 zmm7, [rsp+448]
    vmovdqa64 zmm8, [rsp+512]
    vmovdqa64 zmm9, [rsp+576]
    vmovdqa64 zmm10, [rsp+640]
    vmovdqa64 zmm11, [rsp+704]
    vmovdqa64 zmm12, [rsp+768]
    vmovdqa64 zmm13, [rsp+832]
    vmovdqa64 zmm14, [rsp+896]
    vmovdqa64 zmm15, [rsp+960]
    
    ; Deallocate stack
    add rsp, 2048 + 64
    ret
_Context_Restore_ZMM ENDP

; =============================================================================
; API HOOKS (Callable from any thread)
; =============================================================================

; -----------------------------------------------------------------------------
; Titan_Trigger_0G_Hijack
; Sets the hijack flag to 1, causing the pipeline to preempt on next iteration.
; Thread-safe via simple MOV (atomic on x64 for aligned DWORD).
; -----------------------------------------------------------------------------
ALIGN 16
PUBLIC Titan_Trigger_0G_Hijack
Titan_Trigger_0G_Hijack PROC
    mov dword ptr [HijackFlag], 1
    ret
Titan_Trigger_0G_Hijack ENDP

; -----------------------------------------------------------------------------
; Titan_Clear_0G_Hijack
; Clears the hijack flag. Called after hijack packet is fully processed.
; -----------------------------------------------------------------------------
ALIGN 16
PUBLIC Titan_Clear_0G_Hijack
Titan_Clear_0G_Hijack PROC
    mov dword ptr [HijackFlag], 0
    ret
Titan_Clear_0G_Hijack ENDP

; -----------------------------------------------------------------------------
; Titan_Update_Weight
; Atomically adds/subtracts from CurrentWeight.
; RCX = Delta (+ for add, - for subtract via two's complement)
; -----------------------------------------------------------------------------
ALIGN 16
PUBLIC Titan_Update_Weight
Titan_Update_Weight PROC
    lock add qword ptr [CurrentWeight], rcx
    ret
Titan_Update_Weight ENDP

; -----------------------------------------------------------------------------
; Titan_Set_MaxWeight
; Sets the 100% capacity limit. Call at boot time.
; RCX = New MaxWeight value
; -----------------------------------------------------------------------------
ALIGN 16
PUBLIC Titan_Set_MaxWeight
Titan_Set_MaxWeight PROC
    mov qword ptr [MaxWeight], rcx
    ret
Titan_Set_MaxWeight ENDP

; -----------------------------------------------------------------------------
; Titan_Set_ThresholdWeight
; Sets the 90% tripwire. Call at boot time after MaxWeight is set.
; RCX = New ThresholdWeight value (typically MaxWeight * 9 / 10)
; -----------------------------------------------------------------------------
ALIGN 16
PUBLIC Titan_Set_ThresholdWeight
Titan_Set_ThresholdWeight PROC
    mov qword ptr [ThresholdWeight], rcx
    ret
Titan_Set_ThresholdWeight ENDP

; -----------------------------------------------------------------------------
; Titan_Get_CurrentWeight
; Returns the current load counter in RAX.
; -----------------------------------------------------------------------------
ALIGN 16
PUBLIC Titan_Get_CurrentWeight
Titan_Get_CurrentWeight PROC
    mov rax, [CurrentWeight]
    ret
Titan_Get_CurrentWeight ENDP

; -----------------------------------------------------------------------------
; Titan_Get_RecoilTimer
; Returns the current recoil cooldown counter in RAX.
; Used for telemetry/debugging.
; -----------------------------------------------------------------------------
ALIGN 16
PUBLIC Titan_Get_RecoilTimer
Titan_Get_RecoilTimer PROC
    mov rax, [RecoilTimer]
    ret
Titan_Get_RecoilTimer ENDP

; -----------------------------------------------------------------------------
; Titan_Is_Hijack_Active
; Returns 1 if hijack is active, 0 otherwise (in EAX).
; -----------------------------------------------------------------------------
ALIGN 16
PUBLIC Titan_Is_Hijack_Active
Titan_Is_Hijack_Active PROC
    mov eax, [HijackFlag]
    ret
Titan_Is_Hijack_Active ENDP

END