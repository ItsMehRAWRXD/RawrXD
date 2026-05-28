; ==============================================================================
; SOVEREIGN INTERRUPT GOVERNANCE
; File: Sovereign_Interrupts.asm
; Role: Hard-Real-Time Governance via APIC Timer and MSI-X
; ==============================================================================

include Sovereign_Common.inc
include Sovereign_FrameABI.inc

EXTERN Sovereign_Supervisor_Loop:PROC

.DATA
    g_APIC_Base         QWORD 0FEE00000h ; Standard APIC physical base
    g_ShadowMapBase     QWORD 080000000h ; SHAM mapped ShadowMap Base
    g_IDT_Timer         QWORD 0 
    g_IDT_MSIX_NVMe     QWORD 0

.CODE

PUBLIC Sovereign_Setup_Interrupt_Governance
Sovereign_Setup_Interrupt_Governance PROC
    ; 1. Route APIC Timer to Supervisor Heartbeat
    lea rax, [Sovereign_Supervisor_Loop]
    mov [g_IDT_Timer], rax
    
    ; 2. Route NVMe MSI-X directly to DMA Completion Shadow Updates
    lea rax, [Sovereign_DMA_Complete_ISR]
    mov [g_IDT_MSIX_NVMe], rax
    
    ret
Sovereign_Setup_Interrupt_Governance ENDP


; ==============================================================================
; Sovereign_DMA_Complete_ISR
; Role: IOMMU Device Interrupt Shadow Map Trigger (Bare Metal++ Heartbeat)
; ==============================================================================
PUBLIC Sovereign_DMA_Complete_ISR
Sovereign_DMA_Complete_ISR PROC
    ; Interrupt Frame setup
    
    ; RAX = completed descriptor index (Interrupt vector mapping logic goes here)
    
    ; Flip ShadowMap state
    mov rbx, [g_ShadowMapBase]
    mov byte ptr [rbx + rax*8], 3 ; SHADOW_STATE_DONE = 3
    
    ; Trigger scheduler tick (no polling required)
    call Sovereign_Supervisor_Loop
    
    ; IRETQ explicitly requested for interrupt exit
    iretq
Sovereign_DMA_Complete_ISR ENDP

END
