; ==============================================================================
; Sovereign_Kernel_Subs.asm
; Consolidated Subsystems & Elite Fiber/Physics for Sovereign Kernel
; ==============================================================================

include Sovereign_Common.inc

.CODE

; --- Gameplay / logic Symbols ---

PUBLIC UpdateVehiclePhysics
UpdateVehiclePhysics PROC
    ; rcx = VEHICLE_STATE pointer
    push rbx
    mov rbx, rcx

    ; Calculate Acceleration (Throttle - Brake)
    movss xmm0, dword ptr [rbx].VEHICLE_STATE.Throttle
    movss xmm1, dword ptr [rbx].VEHICLE_STATE.Brake
    subss xmm0, xmm1

    ; Apply Euler integration to VelocityX
    movss xmm2, dword ptr [rbx].VEHICLE_STATE.VelocityX
    addss xmm2, xmm0
    movss dword ptr [rbx].VEHICLE_STATE.VelocityX, xmm2

    ; Update RPM based on Gear
    mov rax, [rbx].VEHICLE_STATE.CurrentGear
    test rax, rax
    jnz _CalcRPM
    mov rax, 1
_CalcRPM:
    cvtsi2ss xmm3, rax
    mulss xmm2, xmm3
    movss dword ptr [rbx].VEHICLE_STATE.CurrentRPM, xmm2

    pop rbx
    ret
UpdateVehiclePhysics ENDP

PUBLIC CalculateTorque
CalculateTorque PROC
    ; rcx = VEHICLE_STATE pointer
    movss xmm0, dword ptr [rcx].VEHICLE_STATE.CurrentRPM
    movss xmm1, dword ptr [rcx].VEHICLE_STATE.Throttle
    mulss xmm0, xmm1
    mov eax, 1000
    cvtsi2ss xmm2, eax
    divss xmm0, xmm2
    ret
CalculateTorque ENDP

; --- Elite Fiber Management ---

; ------------------------------------------------------------------------------
; PROCEDURE: Sovereign_Fiber_Yield
; Input:  RCX = FIBER_CONTEXT pointer
; Logic: Saves non-volatile registers and returns control to the scheduler.
; ------------------------------------------------------------------------------
PUBLIC Sovereign_Fiber_Yield
Sovereign_Fiber_Yield PROC
    mov [rcx].FIBER_CONTEXT.Register_RBX, rbx
    mov [rcx].FIBER_CONTEXT.Register_RBP, rbp
    mov [rcx].FIBER_CONTEXT.Register_R12, r12
    mov [rcx].FIBER_CONTEXT.Register_R13, r13
    mov [rcx].FIBER_CONTEXT.Register_R14, r14
    mov [rcx].FIBER_CONTEXT.Register_R15, r15
    
    ; Capture the stack pointer for the resume
    mov [rcx].FIBER_CONTEXT.Register_RSP, rsp
    
    ; Control returns to the call site (usually the scheduler loop)
    ret
Sovereign_Fiber_Yield ENDP

; ------------------------------------------------------------------------------
; PROCEDURE: Sovereign_Fiber_Resume
; Input:  RCX = FIBER_CONTEXT pointer
; Logic: Restores context and jumps back into optimized execution.
; ------------------------------------------------------------------------------
PUBLIC Sovereign_Fiber_Resume
Sovereign_Fiber_Resume PROC
    mov rbx, [rcx].FIBER_CONTEXT.Register_RBX
    mov rbp, [rcx].FIBER_CONTEXT.Register_RBP
    mov r12, [rcx].FIBER_CONTEXT.Register_R12
    mov r13, [rcx].FIBER_CONTEXT.Register_R13
    mov r14, [rcx].FIBER_CONTEXT.Register_R14
    mov r15, [rcx].FIBER_CONTEXT.Register_R15
    
    ; Restore stack and resume
    mov rsp, [rcx].FIBER_CONTEXT.Register_RSP
    ret
Sovereign_Fiber_Resume ENDP

END
