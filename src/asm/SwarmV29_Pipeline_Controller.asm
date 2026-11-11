; =============================================================================
; SwarmV29_Pipeline_Controller.asm - Unified Pipeline Controller
; =============================================================================
; Approaching Zero Driver Overhead (AZDO) pipeline controller
; Features: 0G Hijack, 90% Recoil Governor, Hard Capacity Limit
; Date: 2026-07-08
; =============================================================================

INCLUDE SwarmV29_Macros.inc

; =============================================================================
;                            EXPORTS
; =============================================================================
PUBLIC Titan_Trigger_0G_Hijack
PUBLIC Titan_Clear_0G_Hijack
PUBLIC Titan_Update_Weight
PUBLIC Titan_Set_MaxWeight
PUBLIC Titan_Set_ThresholdWeight
PUBLIC Titan_Get_CurrentWeight
PUBLIC Titan_Get_RecoilTimer
PUBLIC Titan_Is_Hijack_Active
PUBLIC SwarmV29_Pipeline_Loop

; =============================================================================
;                            DATA
; =============================================================================
.data

; Pipeline state
ALIGN 64
HijackFlag          DWORD 0        ; 0: Normal, 1: 0G Hijack active
CurrentWeight        QWORD 0        ; Atomic current load counter
MaxWeight            QWORD 128      ; 100% Capacity (default 128)
ThresholdWeight      QWORD 115      ; 90% Tripwire (default 115)
RecoilTimer          QWORD 0        ; 3/30 Hysteresis counter

; Constants
RECOIL_VAL           EQU 3          ; Units to shed per recoil event
COOLDOWN_VAL         EQU 30         ; Cycles before next recoil allowed

; Saved context for hijack
ALIGN 64
SavedZMM0            ZMMWORD 64 DUP (<>)
SavedRFlags          QWORD 0

; =============================================================================
;                            CODE
; =============================================================================
.code

; =============================================================================
; Titan_Trigger_0G_Hijack
; Set hijack flag to 1 (immediate preemption)
;
; Returns: EAX = 0 on success
; =============================================================================
Titan_Trigger_0G_Hijack PROC FRAME
    SWARMV29_ABI_FRAME
    
    ; Save AVX-512 context
    vmovdqu64 zmmword ptr [SavedZMM0 + 0], zmm0
    vmovdqu64 zmmword ptr [SavedZMM0 + 64], zmm1
    vmovdqu64 zmmword ptr [SavedZMM0 + 128], zmm2
    vmovdqu64 zmmword ptr [SavedZMM0 + 192], zmm3
    
    ; Save RFLAGS
    pushfq
    pop QWORD PTR [SavedRFlags]
    
    ; Set hijack flag
    mov DWORD PTR [HijackFlag], 1
    mfence
    
    ; Memory fence to ensure visibility
    sfence
    
    xor eax, eax
    SWARMV29_ABI_EPILOG
Titan_Trigger_0G_Hijack ENDP

; =============================================================================
; Titan_Clear_0G_Hijack
; Clear hijack flag
;
; Returns: EAX = 0 on success
; =============================================================================
Titan_Clear_0G_Hijack PROC FRAME
    SWARMV29_ABI_FRAME
    
    ; Clear hijack flag
    mov DWORD PTR [HijackFlag], 0
    mfence
    
    ; Restore AVX-512 context
    vmovdqu64 zmm0, zmmword ptr [SavedZMM0 + 0]
    vmovdqu64 zmm1, zmmword ptr [SavedZMM0 + 64]
    vmovdqu64 zmm2, zmmword ptr [SavedZMM0 + 128]
    vmovdqu64 zmm3, zmmword ptr [SavedZMM0 + 192]
    
    ; Restore RFLAGS
    push QWORD PTR [SavedRFlags]
    popfq
    
    xor eax, eax
    SWARMV29_ABI_EPILOG
Titan_Clear_0G_Hijack ENDP

; =============================================================================
; Titan_Update_Weight
; Atomic weight add/subtract
;
; RCX = delta (signed)
; Returns: RAX = new weight
; =============================================================================
Titan_Update_Weight PROC FRAME
    SWARMV29_ABI_FRAME
    
    ; Atomic add/subtract
    mov rax, rcx
    lock xadd QWORD PTR [CurrentWeight], rax
    
    ; Return new weight
    add rax, rcx
    
    SWARMV29_ABI_EPILOG
Titan_Update_Weight ENDP

; =============================================================================
; Titan_Set_MaxWeight
; Set 100% capacity limit
;
; RCX = max weight
; Returns: EAX = 0 on success
; =============================================================================
Titan_Set_MaxWeight PROC FRAME
    SWARMV29_ABI_FRAME
    
    mov QWORD PTR [MaxWeight], rcx
    mfence
    
    xor eax, eax
    SWARMV29_ABI_EPILOG
Titan_Set_MaxWeight ENDP

; =============================================================================
; Titan_Set_ThresholdWeight
; Set 90% tripwire
;
; RCX = threshold weight
; Returns: EAX = 0 on success
; =============================================================================
Titan_Set_ThresholdWeight PROC FRAME
    SWARMV29_ABI_FRAME
    
    mov QWORD PTR [ThresholdWeight], rcx
    mfence
    
    xor eax, eax
    SWARMV29_ABI_EPILOG
Titan_Set_ThresholdWeight ENDP

; =============================================================================
; Titan_Get_CurrentWeight
; Get current load
;
; Returns: RAX = current weight
; =============================================================================
Titan_Get_CurrentWeight PROC FRAME
    SWARMV29_ABI_FRAME
    
    mov rax, QWORD PTR [CurrentWeight]
    
    SWARMV29_ABI_EPILOG
Titan_Get_CurrentWeight ENDP

; =============================================================================
; Titan_Get_RecoilTimer
; Get cooldown counter
;
; Returns: RAX = recoil timer
; =============================================================================
Titan_Get_RecoilTimer PROC FRAME
    SWARMV29_ABI_FRAME
    
    mov rax, QWORD PTR [RecoilTimer]
    
    SWARMV29_ABI_EPILOG
Titan_Get_RecoilTimer ENDP

; =============================================================================
; Titan_Is_Hijack_Active
; Check hijack state
;
; Returns: EAX = 1 if active, 0 if not
; =============================================================================
Titan_Is_Hijack_Active PROC FRAME
    SWARMV29_ABI_FRAME
    
    mov eax, DWORD PTR [HijackFlag]
    
    SWARMV29_ABI_EPILOG
Titan_Is_Hijack_Active ENDP

; =============================================================================
; SwarmV29_Pipeline_Loop
; Main pipeline loop with priority chain
;
; Priority Chain:
;   1. 0G Hijack (immediate preemption)
;   2. 90% Recoil Governor (3/30 hysteresis)
;   3. Hard Capacity Check (100% backpressure)
;   4. Dispatch: SwarmV29_NTT_Butterfly
;
; RCX = input buffer pointer
; RDX = output buffer pointer
; R8  = buffer size (bytes)
; R9  = iterations
;
; Returns: RAX = 0 on success, -1 on failure
; =============================================================================
SwarmV29_Pipeline_Loop PROC FRAME
    SWARMV29_ABI_FRAME
    
    mov r12, rcx            ; r12 = input buffer
    mov r13, rdx            ; r13 = output buffer
    mov r14, r8             ; r14 = buffer size
    mov r15, r9             ; r15 = iterations
    
    xor rbx, rbx            ; iteration counter
    
@@pipeline_loop:
    ; Check iteration limit
    cmp rbx, r15
    jge @@pipeline_done
    
    ; ========================================
    ; Priority 1: 0G Hijack (immediate preemption)
    ; ========================================
    mov eax, DWORD PTR [HijackFlag]
    test eax, eax
    jnz @@hijack_active
    
    ; ========================================
    ; Priority 2: 90% Recoil Governor
    ; ========================================
    mov rax, QWORD PTR [CurrentWeight]
    cmp rax, QWORD PTR [ThresholdWeight]
    jb @@under_threshold
    
    ; At or above 90% threshold
    mov rax, QWORD PTR [RecoilTimer]
    test rax, rax
    jnz @@skip_shed          ; Timer > 0, skip shed
    
    ; Timer == 0, shed RECOIL_VAL units
    SWARMV29_ATOMIC_SUB CurrentWeight, RECOIL_VAL
    mov QWORD PTR [RecoilTimer], COOLDOWN_VAL
    jmp @@drop_packet
    
@@skip_shed:
    ; Decrement timer
    SWARMV29_ATOMIC_DEC RecoilTimer
    jmp @@check_hard_limit
    
@@under_threshold:
    ; Under 90% - clear timer
    mov QWORD PTR [RecoilTimer], 0
    
@@check_hard_limit:
    ; ========================================
    ; Priority 3: Hard Capacity Check (100% backpressure)
    ; ========================================
    mov rax, QWORD PTR [CurrentWeight]
    cmp rax, QWORD PTR [MaxWeight]
    jae @@drop_packet
    
    ; ========================================
    ; Priority 4: Dispatch to NTT Butterfly
    ; ========================================
    ; Call SwarmV29_NTT_Butterfly (external)
    ; For now, just copy data
    mov rsi, r12
    mov rdi, r13
    mov rcx, r14
    rep movsb
    
    ; Increment weight
    SWARMV29_ATOMIC_INC CurrentWeight
    
    ; Next iteration
    inc rbx
    jmp @@pipeline_loop
    
@@hijack_active:
    ; 0G Hijack - immediate preemption
    ; Save context and return
    mov rax, -2            ; Special return code for hijack
    jmp @@done
    
@@drop_packet:
    ; Drop packet due to backpressure
    inc rbx
    jmp @@pipeline_loop
    
@@pipeline_done:
    xor rax, rax
    
@@done:
    SWARMV29_ABI_EPILOG
SwarmV29_Pipeline_Loop ENDP

; =============================================================================
; SwarmV29_Decay_RecoilTimer
; Decrement recoil timer (call from main loop)
; =============================================================================
SwarmV29_Decay_RecoilTimer PROC FRAME
    SWARMV29_ABI_FRAME
    
    mov rax, QWORD PTR [RecoilTimer]
    test rax, rax
    jz @@done
    
    ; Decrement timer
    SWARMV29_ATOMIC_DEC RecoilTimer
    
@@done:
    SWARMV29_ABI_EPILOG
SwarmV29_Decay_RecoilTimer ENDP

END