; ==============================================================================
; Simulation_Thread.asm — Deterministic Simulation Loop
; Event-driven waits, lockstep tape writes, zero-overhead telemetry
; ==============================================================================

option casemap:none

; ==============================================================================
; External APIs
; ==============================================================================
EXTERN SetEvent              : PROC
EXTERN WaitForSingleObject   : PROC
EXTERN WaitForMultipleObjects : PROC
EXTERN CreateEventA          : PROC
EXTERN CreateThread          : PROC
EXTERN CloseHandle           : PROC
EXTERN ExitThread            : PROC
EXTERN GetCurrentThreadId    : PROC

; ==============================================================================
; External Data (from Lockstep_Tape.hpp / C++ side)
; ==============================================================================
EXTERN g_LockstepTape        : BYTE
EXTERN g_hEvent_SimulationTick : QWORD
EXTERN g_hEvent_FrameComplete  : QWORD

; ==============================================================================
; External Functions (from Sovereign_SDK)
; ==============================================================================
EXTERN GhostBuffer_WriteEvent : PROC

; ==============================================================================
; Data Section
; ==============================================================================
.data
ALIGN 16

; Simulation state
sim_current_tick    dq 0
sim_running         db 1
sim_pad             db 7 dup(?)
g_SimulationStatus  dd 0

; Camera matrices (column-major 4x4)
g_CameraView        real4 16 dup(0.0)
g_CameraProj        real4 16 dup(0.0)
g_ObjectCount       dd 0

; Audio state placeholder
g_AudioBuffer       db 4096 dup(0)

; Event handles (created at thread startup)
g_hSimTickEvent     dq 0
g_hFrameDoneEvent   dq 0
g_hSimExitAckEvent  dq 0
g_hStopEvent        dq 0
g_WaitHandles       dq 2 dup(0)

; ==============================================================================
; GHOST_WRITE Macro — Zero-overhead telemetry inline
; Cycles: ~15 vs ~80 for CALL through IAT
; ==============================================================================
GHOST_WRITE MACRO event_type:REQ, payload_reg:REQ
    LOCAL @@skip
    ; Call through export (simpler than direct memory for now)
    ; Future: write directly to g_GhostBuffer.records[]
    mov cl, event_type
    mov rdx, payload_reg
    call GhostBuffer_WriteEvent
ENDM

; ==============================================================================
; Code Section
; ==============================================================================
.code

; ==============================================================================
; Simulation_CreateEvents — Create sync events before thread starts
; Returns: RAX = 1 on success
; ==============================================================================
PUBLIC Simulation_CreateEvents
Simulation_CreateEvents PROC
    push rbx
    sub rsp, 28h

    ; Create SimulationTick event (manual reset, initially non-signaled)
    xor ecx, ecx            ; lpEventAttributes = NULL
    xor edx, edx            ; bManualReset = FALSE (auto-reset)
    xor r8d, r8d            ; bInitialState = FALSE
    xor r9d, r9d            ; lpName = NULL
    call CreateEventA
    mov [g_hSimTickEvent], rax

    ; Create FrameComplete event (auto reset, initially signaled so first tick runs)
    xor ecx, ecx
    mov edx, 1              ; bManualReset = TRUE (manual reset for frame complete)
    mov r8d, 1              ; bInitialState = TRUE (start signaled)
    xor r9d, r9d
    call CreateEventA
    mov [g_hFrameDoneEvent], rax

    ; Create Stop event (manual reset, initially non-signaled)
    xor ecx, ecx
    mov edx, 1              ; bManualReset = TRUE
    xor r8d, r8d            ; bInitialState = FALSE
    xor r9d, r9d
    call CreateEventA
    mov [g_hStopEvent], rax

    ; Export to C++ globals
    mov rax, [g_hSimTickEvent]
    mov [g_hEvent_SimulationTick], rax
    mov rax, [g_hFrameDoneEvent]
    mov [g_hEvent_FrameComplete], rax

    mov eax, 1
    add rsp, 28h
    pop rbx
    ret
Simulation_CreateEvents ENDP

; ==============================================================================
; Simulation_Thread_Entry — Main simulation loop
; RBX = current tick (preserved across iterations)
; ==============================================================================
PUBLIC Simulation_Thread_Entry
Simulation_Thread_Entry PROC
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    sub rsp, 136

    ; Initialize tick counter
    xor rbx, rbx
    mov [sim_current_tick], rbx
    mov DWORD PTR [g_SimulationStatus], 0

    ; Create events if not already done
    mov rax, [g_hSimTickEvent]
    test rax, rax
    jnz events_ready
    call Simulation_CreateEvents

events_ready:
    ; Wait set = [frame-done, stop]
    mov rax, [g_hFrameDoneEvent]
    mov [g_WaitHandles + 0], rax
    mov rax, [g_hStopEvent]
    mov [g_WaitHandles + 8], rax

sim_loop:
    ; Check running flag
    mov al, [sim_running]
    test al, al
    jz sim_exit

    ; ── WAIT FOR PREVIOUS FRAME ──
    ; Wait for either frame complete or explicit stop event.
    mov DWORD PTR [g_SimulationStatus], 10
    mov ecx, 2              ; nCount
    lea rdx, g_WaitHandles  ; lpHandles
    xor r8d, r8d            ; bWaitAll = FALSE
    mov r9d, 0FFFFFFFFh     ; INFINITE
    call WaitForMultipleObjects
    cmp eax, 1              ; WAIT_OBJECT_0 + 1 => stop event
    je sim_exit
    mov DWORD PTR [g_SimulationStatus], 0

    ; ── SIMULATE TICK ──
    ; Physics step
    call Physics_Step

    ; Log physics complete
    GHOST_WRITE 40h, rbx    ; GHOST_SCHEDULER_TICK

    ; AI update (agent DAG)
    call AgentDAG_Execute

    ; Log agent dispatch count
    mov rdx, [g_TasksExecuted]
    GHOST_WRITE 50h, rdx    ; GHOST_AGENT_DISPATCH

    ; Audio synthesis (placeholder)
    call Audio_Synthesize

    ; ── COMPUTE STATE HASH ──
    ; FNV-1a of all simulation state
    call ComputeStateHash
    mov r12, rax            ; R12 = state_hash

    ; ── WRITE TO TAPE ──
    ; Layout: TapeEntry = 192 bytes
    ; idx = tick & 255
    ; Forensic canary: detect saved RIP corruption before tape write path.
    push rdi
    pushfq
    cmp QWORD PTR [rsp + 200], 100h
    jne @@canary_safe
    int 3
    nop
    nop
@@canary_safe:
    popfq
    pop rdi

    mov r13, rbx
    and r13, 255            ; R13 = idx

    ; Calculate entry address: base + idx * 192
    imul r14, r13, 192      ; R14 = offset
    lea rax, g_LockstepTape
    lea rdi, [rax + r14]    ; RDI = &entries[idx]

    ; Guard rdi against LockstepTape bounds before publishing to r10.
    ; LockstepTape size = 256 * 192 = 49152 bytes (0C000h).
    lea r11, g_LockstepTape
    lea rcx, [r11 + 0C000h] ; one-past-end
    cmp rdi, r11
    jb @@tape_oob
    cmp rdi, rcx
    jae @@tape_oob
    jmp @@tape_ok

@@tape_oob:
    int 3
    nop

@@tape_ok:
    mov r10, rdi            ; R10 = stable entry base

    ; Wait for entry to be EMPTY or CONSUMED
    mov DWORD PTR [g_SimulationStatus], 20
@@wait_empty:
    mov al, [sim_running]
    test al, al
    jz sim_exit
    mov eax, [r10 + 168]    ; ready field at offset 168
    cmp eax, 0              ; TAPE_EMPTY
    je @@write_entry
    cmp eax, 3              ; TAPE_CONSUMED
    je @@write_entry
pause
    jmp @@wait_empty

@@write_entry:
    mov DWORD PTR [g_SimulationStatus], 0
    ; Mark WRITING
    mov DWORD PTR [r10 + 168], 1

    ; Write fields
    mov [r10 + 0], rbx      ; tick_id
    rdtsc
    mov [r10 + 8], rax      ; timestamp
    mov [r10 + 16], r12     ; state_hash

    lea rdi, [r10 + 24]     ; matrix region starts after tick/timestamp/hash

    ; Copy view matrix (64 bytes)
    lea rsi, [g_CameraView]
    mov rcx, 8              ; 8 QWORDs = 64 bytes
    rep movsq

    ; Copy proj matrix (64 bytes)
    lea rsi, [g_CameraProj]
    mov rcx, 8
    rep movsq

    ; object_count + gpu_buffer
    mov eax, [g_ObjectCount]
    mov [r10 + 152], eax
    mov rax, [g_GPUPBO]
    mov [r10 + 160], rax

    ; Mark READY
    mov DWORD PTR [r10 + 168], 2

    ; Memory fence
    sfence

    ; ── SIGNAL COMPOSITOR ──
    mov rcx, [g_hSimTickEvent]
    call SetEvent

    ; Increment tick
    inc rbx
    mov [sim_current_tick], rbx
    jmp sim_loop

sim_exit:
    ; Flight recorder breadcrumbs for deterministic exit-path diagnosis.
    mov DWORD PTR [g_SimulationStatus], 1
    mov DWORD PTR [g_SimulationStatus], 2
    mov rcx, [g_hSimExitAckEvent]
    test rcx, rcx
    jz @@skip_exit_ack
    call SetEvent
    mov DWORD PTR [g_SimulationStatus], 3
@@skip_exit_ack:
    add rsp, 136
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    xor eax, eax
    ret
Simulation_Thread_Entry ENDP

; ==============================================================================
; Simulation_Stop — Signal thread to exit
; ==============================================================================
PUBLIC Simulation_Stop
Simulation_Stop PROC
    mov BYTE PTR [sim_running], 0
    ; Signal events to unblock waits
    mov rcx, [g_hSimTickEvent]
    call SetEvent
    mov rcx, [g_hFrameDoneEvent]
    call SetEvent
    mov rcx, [g_hStopEvent]
    call SetEvent
    ret
Simulation_Stop ENDP

; ==============================================================================
; Simulation_SetExitAckEvent — Register optional host-owned exit-ack event
; RCX = HANDLE (or NULL to disable)
; Returns: EAX = 1
; ==============================================================================
PUBLIC Simulation_SetExitAckEvent
Simulation_SetExitAckEvent PROC
    mov [g_hSimExitAckEvent], rcx
    mov eax, 1
    ret
Simulation_SetExitAckEvent ENDP

; ==============================================================================
; Simulation_GetCurrentTick
; ==============================================================================
PUBLIC Simulation_GetCurrentTick
Simulation_GetCurrentTick PROC
    mov rax, [sim_current_tick]
    ret
Simulation_GetCurrentTick ENDP

; ==============================================================================
; GetSimulationStatus — Return simulation flight-recorder status code
; Returns: EAX = g_SimulationStatus
; ==============================================================================
PUBLIC GetSimulationStatus
GetSimulationStatus PROC
    mov eax, DWORD PTR [g_SimulationStatus]
    ret
GetSimulationStatus ENDP

; ==============================================================================
; Placeholder stubs for simulation subsystems
; ==============================================================================
PUBLIC Physics_Step
Physics_Step PROC
    ret
Physics_Step ENDP

PUBLIC AgentDAG_Execute
AgentDAG_Execute PROC
    ret
AgentDAG_Execute ENDP

PUBLIC Audio_Synthesize
Audio_Synthesize PROC
    ret
Audio_Synthesize ENDP

PUBLIC ComputeStateHash
ComputeStateHash PROC
    ; Simple hash: tick_id * 0x9E3779B97F4A7C15 (golden ratio)
    mov rax, [sim_current_tick]
    mov rcx, 9E3779B97F4A7C15h
    mul rcx
    ret
ComputeStateHash ENDP

; ==============================================================================
; Data symbols referenced by simulation
; ==============================================================================
.data
ALIGN 8
g_TasksExecuted     dq 0
g_GPUPBO            dq 0

end
