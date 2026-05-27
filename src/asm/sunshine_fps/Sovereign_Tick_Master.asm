EXTERN Sovereign_Compositor_Render:PROC
; =========================================================================================
; Sovereign_Tick_Master.asm
; Deterministic Transport Layer - Root Clock & Tick Authority
; RULE 1: ONLY TITAN_LOOP DRIVES SIMULATION.
; RULE 2: Render/Audio/Network DO NOT drive simulation. Advisory outputs only.
; =========================================================================================

.data
    align 8
    Sovereign_CurrentTick       dq 0
    Sovereign_Accumulator       dq 0        ; Time accumulated 
    Sovereign_FixedTimeStep     dq 16666    ; 60Hz fractional base
    Sovereign_OverrunThreshold  dq 166660   ; Cap death spiral at 10 frames worth
    Sovereign_FrameOverrunCount dq 0
    Sovereign_StateHash         dq 0        ; Fingerprint of current deterministic simulation state

    ; Simulation tracking for Ghost Buffer validation
    Sim_TotalTokens             REAL8 0.0
    Sim_CurrentTPS              REAL8 5.0   ; Start at heater phase (low TPS)
    Sim_TPS_Accel               REAL8 0.05  ; Accelerate linearly each tick to trigger derivative
    TokenText                   DB "T", 0

.code
    extern Sovereign_Benchmark_Step:PROC
    extern Sovereign_Ghost_PushToken:PROC
    extern Sovereign_Input_Poll:PROC
    extern Sovereign_Tape_Append:PROC
    extern Sovereign_HID_Poll:PROC


; -----------------------------------------------------------------------------------------
; Sovereign_Tick_Init
; Zeroes clock state. Prepared for start of determinism tape.
; -----------------------------------------------------------------------------------------
align 16
Sovereign_Tick_Init PROC
    xor rax, rax
    mov [Sovereign_CurrentTick], rax
    mov [Sovereign_Accumulator], rax
    mov [Sovereign_FrameOverrunCount], rax
    mov [Sovereign_StateHash], rax
    ret
Sovereign_Tick_Init ENDP

; -----------------------------------------------------------------------------------------
; Sovereign_Tick_Master 
; RCX = DeltaTime (raw measurement units passed from external high-perf timer)
; -----------------------------------------------------------------------------------------
align 16
Sovereign_Tick_Master PROC
    push rbx
    push rsi
    push rdi

    ; 1) Fixed Timestep Accumulator
    mov rax, [Sovereign_Accumulator]
    add rax, rcx

    ; 2) Frame Overrun Recovery / Death Spiral Protection
    mov rdx, [Sovereign_OverrunThreshold]
    cmp rax, rdx
    jle L_Accumulator_Safe
    
    ; Cap accumulator and log an overrun
    mov rax, rdx
    inc qword ptr [Sovereign_FrameOverrunCount]

L_Accumulator_Safe:
    mov [Sovereign_Accumulator], rax

L_Titan_Loop_Start:
    ; While Accumulator >= FixedTimeStep
    mov rax, [Sovereign_Accumulator]
    mov rdx, [Sovereign_FixedTimeStep]
    cmp rax, rdx
    jl L_Titan_Loop_End

    ; Consume a discrete, deterministic quantum of time
    sub rax, rdx
    mov [Sovereign_Accumulator], rax

    ; =====================================================================================
    ; [ DETERMINISTIC TICK AUTHORITY ]
    ; Execution happens ONLY inside this boundary. Everything outside is just rendering/audio.
    ; =====================================================================================
    
    ; Drain RawInput messages into accumulators
    call Sovereign_HID_Poll

    ; 1. Allocate 20 bytes on stack for frame + 8 align
    sub rsp, 24
    mov rcx, rsp
    mov rdx, [Sovereign_CurrentTick]   ; tick_id
    call Sovereign_Input_Poll          ; Quantizer: raw HID ? 20-byte frame

    ; 2. Record to lockstep tape
    mov rcx, rsp
    call Sovereign_Tape_Append         ; Lock-free append

    ; 3. Advance simulation with deterministic frame now resident
    ; ... Titan Loop body executes here ...
    
    add rsp, 24                        ; Reclaim stack

    ; --- LIVE TOKEN STREAM SIMULATION (Heater -> Fling) ---
    push rcx
    push rdx
    
    ; Increase tokens generated tracking variables
    fld1
    fadd qword ptr [Sim_TotalTokens]
    fstp qword ptr [Sim_TotalTokens]
    
    ; Simulate an acceleration curve for TPS to trigger the Fling/LATCH
    fld qword ptr [Sim_CurrentTPS]
    fadd qword ptr [Sim_TPS_Accel]
    fstp qword ptr [Sim_CurrentTPS]
    
    ; Call Benchmark Step
    movsd xmm0, qword ptr [Sim_CurrentTPS]
    movsd xmm1, qword ptr [Sim_TotalTokens]
    sub rsp, 32
    call Sovereign_Benchmark_Step
    add rsp, 32
    
    ; Push Token to Lock-Free Buffer
    lea rcx, [TokenText]
    sub rsp, 32
    call Sovereign_Ghost_PushToken
    add rsp, 32
    
    pop rdx
    pop rcx
    ; ------------------------------------------------------
    
    ; Increment root clock for entire framework
    inc qword ptr [Sovereign_CurrentTick]

    jmp L_Titan_Loop_Start

L_Titan_Loop_End:
    call Sovereign_Compositor_Render
    ; 3) Render Snapshot Staging

    pop rdi
    pop rsi
    pop rbx
    ret
Sovereign_Tick_Master ENDP

END

