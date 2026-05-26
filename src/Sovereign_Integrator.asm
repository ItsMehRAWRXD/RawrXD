; Sovereign_Integrator.asm - Zero-dependency symplectic kernel
.CODE

; p_q: Pointer to Q (Position), p_p: Pointer to P (Momentum), 
; p_dt: Step size, p_grad: Gradient function pointer
PUBLIC Integrate_Hamiltonian_Step
Integrate_Hamiltonian_Step PROC
    ; RCX=q, RDX=p, R8=dt, R9=grad_func
    
    ; 1. Half-step momentum: p = p - 0.5 * dt * grad(q)
    sub rsp, 40
    mov [rsp+32], r9
    call r9             ; Compute grad(q) -> XMM0
    
    movss xmm1, dword ptr [r8]    ; Load dt
    mulss xmm1, dword ptr [float_0_5]
    mulss xmm0, xmm1
    movss xmm2, dword ptr [rdx]   ; Load p
    subss xmm2, xmm0
    movss dword ptr [rdx], xmm2   ; Store updated p
    
    ; 2. Full-step position: q = q + dt * p
    movss xmm0, dword ptr [rcx]
    movss xmm1, dword ptr [r8]
    mulss xmm1, xmm2
    addss xmm0, xmm1
    movss dword ptr [rcx], xmm0
    
    ; 3. Half-step momentum: Finalize p
    mov r9, [rsp+32]
    call r9             ; Compute grad(q) -> XMM0
    
    movss xmm1, dword ptr [r8]
    mulss xmm1, dword ptr [float_0_5]
    mulss xmm0, xmm1
    movss xmm2, dword ptr [rdx]
    subss xmm2, xmm0
    movss dword ptr [rdx], xmm2   ; Store final p
    
    add rsp, 40
    ret
Integrate_Hamiltonian_Step ENDP

.DATA
float_0_5 dd 03f000000h ; IEEE 754 hex for 0.5f

END