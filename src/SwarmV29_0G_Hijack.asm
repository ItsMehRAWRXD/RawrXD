; ==============================================================================
; SwarmV29_0G_Hijack.asm
; Final Integrated Pipeline Controller — "Bearing on a Bearing" Core
; Integrates: Atomic 0G Hijack, 90% Recoil Governor, 100% Hard Limit
; Dependencies: Zero (pure MASM, no CRT)
; ==============================================================================

.data
    ALIGN 8
    PUBLIC HijackFlag      ; 0: Gravity, 1: 0G Hijack
    HijackFlag DWORD 0
    
    PUBLIC CurrentWeight   ; Atomic current load
    CurrentWeight QWORD 0
    
    PUBLIC MaxWeight       ; 100% Capacity
    MaxWeight QWORD 128
    
    PUBLIC ThresholdWeight ; 90% Tripwire
    ThresholdWeight QWORD 115
    
    PUBLIC RecoilTimer     ; 3/30 Governor
    RecoilTimer QWORD 0
    
    RECOIL_VAL     EQU 3
    COOLDOWN_VAL   EQU 30

.code
    EXTERN SwarmV29_NTT_Butterfly : PROC
    EXTERN Process_ZeroG_Packet    : PROC

; ==============================================================================
; SwarmV29_Pipeline_Controller
; The "Bearing on a Bearing" Core
; ==============================================================================
SwarmV29_Pipeline_Controller PROC
    push rbp
    mov rbp, rsp
    
Pipeline_Loop:
    ; 1. PRIORITY 1: 0G HIJACK (Atomic Preemption)
    mov eax, [HijackFlag]
    test eax, eax
    jnz _0G_Hijack_Sequence

    ; 2. PRIORITY 2: GOVERNOR & TRIPWIRE (90% + 3/30 Recoil)
    mov rax, [CurrentWeight]
    cmp rax, [ThresholdWeight]
    jae _Recoil_Governor_Check

_Governor_CoolDown:
    cmp qword ptr [RecoilTimer], 0
    je _Check_Hard_Limit
    dec qword ptr [RecoilTimer]

_Check_Hard_Limit:
    ; 3. PRIORITY 3: HARD CAPACITY CHECK (100%)
    mov rax, [CurrentWeight]
    cmp rax, [MaxWeight]
    jae Pipeline_Loop             ; Backpressure (Spin)

    ; 4. DISPATCH
    call SwarmV29_NTT_Butterfly
    jmp Pipeline_Loop

_Recoil_Governor_Check:
    cmp qword ptr [RecoilTimer], 0
    jne _Check_Hard_Limit         ; Cooldown active
    
    ; Perform Recoil (3 units)
    lock sub [CurrentWeight], RECOIL_VAL
    mov qword ptr [RecoilTimer], COOLDOWN_VAL
    jmp Pipeline_Loop             ; Drop packet & Reset

_0G_Hijack_Sequence:
    ; ======================================================================
    ; MEMORY VISIBILITY PATCH (fence_violation fix)
    ; ======================================================================
    ; PRE-SYNC: Ensure all prior pipeline ops are globally visible
    ; before entering hijack sequence. Prevents Store Buffer from
    ; reordering flag reads before ZMM context is committed.
    ; ======================================================================
    mfence
    
    ; Context Save: Spill ZMM0-31 to aligned stack (2048 bytes)
    call _Context_Save_ZMM
    
    ; Hijack Execution: 0G packet processing
    call Process_ZeroG_Packet
    
    ; POST-SYNC: Ensure ZMM save and 0G processing are fully committed
    ; before restoring context. Prevents trailing threads from seeing
    ; stale ZMM state.
    mfence
    
    ; Context Restore: Reload ZMM0-31 from aligned stack
    call _Context_Restore_ZMM
    
    ; FLAG RESET: Clear hijack flag with full memory barrier
    ; Ensures flag update is visible to all cores before resuming
    mov dword ptr [HijackFlag], 0
    mfence
    
    jmp Pipeline_Loop
SwarmV29_Pipeline_Controller ENDP

; ==============================================================================
; Context Management (Preserve ZMM0-31)
; ==============================================================================
_Context_Save_ZMM PROC
    sub rsp, 2048 + 64
    and rsp, -64
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

_Context_Restore_ZMM PROC
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
    add rsp, 2048 + 64
    ret
_Context_Restore_ZMM ENDP

; ==============================================================================
; Titan_Trigger_0G_Hijack
; Atomic Trigger — callable from any thread without synchronization primitives.
; Under x86-64 TSO, a simple mov is sufficient for cross-thread visibility.
; ==============================================================================
ALIGN 16
PUBLIC Titan_Trigger_0G_Hijack
Titan_Trigger_0G_Hijack PROC
    mov dword ptr [HijackFlag], 1
    ret
Titan_Trigger_0G_Hijack ENDP

; ==============================================================================
; Titan_Clear_0G_Hijack
; Manual reset — used if Process_ZeroG_Packet does not self-clear.
; ==============================================================================
ALIGN 16
PUBLIC Titan_Clear_0G_Hijack
Titan_Clear_0G_Hijack PROC
    mov dword ptr [HijackFlag], 0
    ret
Titan_Clear_0G_Hijack ENDP

; ==============================================================================
; SwarmV29_SetMaxWeight
; Configure the 100% capacity limit at runtime.
; RCX = new MaxWeight value
; ==============================================================================
ALIGN 16
PUBLIC SwarmV29_SetMaxWeight
SwarmV29_SetMaxWeight PROC
    mov [MaxWeight], rcx
    ret
SwarmV29_SetMaxWeight ENDP

; ==============================================================================
; SwarmV29_SetThresholdWeight
; Configure the 90% tripwire at runtime.
; RCX = new ThresholdWeight value
; ==============================================================================
ALIGN 16
PUBLIC SwarmV29_SetThresholdWeight
SwarmV29_SetThresholdWeight PROC
    mov [ThresholdWeight], rcx
    ret
SwarmV29_SetThresholdWeight ENDP

; ==============================================================================
; SwarmV29_GetCurrentWeight
; Query the current load (for telemetry).
; Returns: RAX = CurrentWeight
; ==============================================================================
ALIGN 16
PUBLIC SwarmV29_GetCurrentWeight
SwarmV29_GetCurrentWeight PROC
    mov rax, [CurrentWeight]
    ret
SwarmV29_GetCurrentWeight ENDP

END
