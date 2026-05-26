include Sovereign_Common.inc

extern Sovereign_PEB_Bootstrap : proc
extern Integrate_Hamiltonian_Step : proc
extern g_ApiTable : SOVEREIGN_API_TABLE

.DATA
    ; Initial tracking values
    q_val  dd 03f800000h ; 1.0f
    p_val  dd 000000000h ; 0.0f
    dt_val dd 03c23d70ah ; 0.01f

.CODE

; Dummy Gradient Field V(q)=0.5*q^2 -> grad=q
; In a real run, this fetches the weight gradient pointer for the current layer
DummyGrad_Physics_Field PROC
    movss xmm0, dword ptr [rcx]
    ret
DummyGrad_Physics_Field ENDP

PUBLIC main
main PROC
    sub rsp, 40
    
    ; 1. PEB/API Bootstrap (for safe process exit bypassing CRT)
    call Sovereign_PEB_Bootstrap

    ; 2. Set Iterations for Benchmarking (10 Million Leapfrog computations)
    mov r14, 10000000

@bench_loop:
    lea rcx, q_val
    lea rdx, p_val
    lea r8, dt_val
    lea r9, DummyGrad_Physics_Field
    call Integrate_Hamiltonian_Step

    dec r14
    jnz @bench_loop

    ; 3. Terminate cleanly
    xor rcx, rcx
    call [g_ApiTable.pExitProcess]

main ENDP

END