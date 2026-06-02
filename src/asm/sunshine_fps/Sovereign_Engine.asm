; ==============================================================================
; SOVEREIGN_ENGINE.ASM
; The Heartbeat Loop and Integrity Gate
; ==============================================================================
INCLUDE Sovereign_Types.inc

_DATA SEGMENT
    ALIGN 16
    Uniform_Time        REAL4 0.0
    Uniform_Time_Delta  REAL4 0.015 ; Orbital speed
_DATA ENDS

_TEXT SEGMENT 'CODE'
    PUBLIC Sovereign_Fabric_Loop
    PUBLIC Sovereign_Lane_Entry

; ==============================================================================
; MAIN FABRIC LOOP (Lane 0)
; ==============================================================================
Sovereign_Fabric_Loop PROC
    extern Sovereign_Compositor_Init:PROC
    mov rcx, 1280
    mov rdx, 720
    sub rsp, 32
    call Sovereign_Compositor_Init
    add rsp, 32
    cmp rax, 1
    jne @@Init_Fail

    xor rcx, rcx ; We are Lane 0
@@Tick:
    ; 1. Root Clock / Tick Master
    extern Sovereign_Tick_Master : PROC
    mov rcx, 16666 ; Provide constant 16.6ms delta for now
    sub rsp, 32
    call Sovereign_Tick_Master
    add rsp, 32

    ; 2. Update Uniform Time (Once per frame, in Lane 0)
    movss xmm0, [Uniform_Time]
    addss xmm0, [Uniform_Time_Delta]
    movss [Uniform_Time], xmm0
    
    ; Compute fsincos via x87 for Host Uniforms
    sub rsp, 8
    movss dword ptr [rsp], xmm0
    fld dword ptr [rsp]
    fsincos
    ; fsincos computes cosine and sine. ST(0) = cos, ST(1) = sin
    fstp dword ptr [g_FabricContext + SOVEREIGN_FABRIC_CONTEXT.Beacon_Registers + 0]  ; Cosine -> Beacon[0]
    fstp dword ptr [g_FabricContext + SOVEREIGN_FABRIC_CONTEXT.Beacon_Registers + 8]  ; Sine   -> Beacon[1]
    add rsp, 8

    ; 2. Licensing Gate
    extern Verify_Sovereign_Licence : PROC
    call Verify_Sovereign_Licence
    test rax, rax
    jnz @@Breach
    
    ; 2. Integrity Check
    call Verify_Arena_Integrity
    
    ; 3. Barrier Pulse
    xor rcx, rcx                    ; Lane 0
    call Sovereign_Fabric_Barrier
    
    ; 4. Vectorized Compute (Lane 0)
    extern Sovereign_Compute_Kernel : PROC
    xor rcx, rcx                    ; Lane 0
    call Sovereign_Compute_Kernel
    
    ; 5. IDE Monitor Snapshot
    extern Sovereign_IDE_Monitor : PROC
    call Sovereign_IDE_Monitor
    
    ; 6. Format Telemetry HUD
    extern Sovereign_Format_HUD : PROC
    call Sovereign_Format_HUD
    
    lfence
    jmp @@Tick

@@Breach:
    cli
    hlt

@@Init_Fail:
    extern ExitProcess:PROC
    mov ecx, eax ; Return the error code we got from init
    call ExitProcess

Sovereign_Fabric_Loop ENDP

; ==============================================================================
; SECONDARY LANE ENTRY (Lanes 1-15)
; ==============================================================================
Sovereign_Lane_Entry PROC
    ; rcx = Lane ID (passed during thread creation)
    and rsp, -16
    lea r15, [g_FabricContext]
    mov r14, rcx ; Preserve Lane ID in R14
@@LaneTick:
    mov rcx, r14
    call Sovereign_Fabric_Barrier
    
    ; Lane-Specific Logic
    mov rcx, r14
    call Sovereign_Compute_Kernel
    
    jmp @@LaneTick
Sovereign_Lane_Entry ENDP

; ==============================================================================
; THE BARRIER PROTOCOL (Option C)
; ==============================================================================
Sovereign_Fabric_Barrier PROC
    ; r15: Context Pointer
    ; rcx: Current Lane ID
    
    ; 1. Mark current lane as Waiting (Status 3)
    mov rdx, rcx
    shl rdx, 6 ; offset (Lane Size=64)
    lea rbx, [r15 + SOVEREIGN_FABRIC_CONTEXT.Lanes]
    add rbx, rdx
    mov QWORD PTR [rbx + SOVEREIGN_LANE.Status], 3
    
    cmp rcx, 0
    jne @@WaitForPulse

    ; --- LANE 0 ACTION: THE DISPATCHER ---
@@Lane0Pulse:
    xor r8, r8
    inc r8 ; Start checking from Lane 1
@@CheckOne:
    mov r9, r8
    shl r9, 6
    lea r9, [r15 + SOVEREIGN_FABRIC_CONTEXT.Lanes + r9]
@@PollOne:
    pause
    cmp QWORD PTR [r9 + SOVEREIGN_LANE.Status], 3
    jne @@PollOne
    inc r8
    cmp r8, SOVEREIGN_LANE_COUNT
    jne @@CheckOne

    ; All lanes locked in barrier. Advance the Pulse.
    lock inc QWORD PTR [r15 + SOVEREIGN_FABRIC_CONTEXT.Fence_State]
    
    ; Reset all to Busy (Status 2)
    xor r8, r8
@@ResetLoop:
    mov r9, r8
    shl r9, 6
    lea r9, [r15 + SOVEREIGN_FABRIC_CONTEXT.Lanes + r9]
    mov QWORD PTR [r9 + SOVEREIGN_LANE.Status], 2
    inc r8
    cmp r8, SOVEREIGN_LANE_COUNT
    jne @@ResetLoop
    ret

    ; --- WORKER ACTION: POLLING THE PULSE ---
@@WaitForPulse:
    mov rax, [r15 + SOVEREIGN_FABRIC_CONTEXT.Fence_State]
@@PollFence:
    pause
    cmp rax, [r15 + SOVEREIGN_FABRIC_CONTEXT.Fence_State]
    je @@PollFence
    ret
Sovereign_Fabric_Barrier ENDP

Verify_Arena_Integrity PROC
    ret
Verify_Arena_Integrity ENDP

_TEXT ENDS
END

