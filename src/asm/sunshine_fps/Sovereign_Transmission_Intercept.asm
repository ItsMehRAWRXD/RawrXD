; Sovereign_Transmission_Intercept.asm
; x64 MASM — Zero Dependency
; Wires Inflection_Feed into 8-Gear Transmission

.data
    ; Extern from Inflection Detector
    extern current_state:DWORD
    extern latch_4th:BYTE
    extern pin_point:DWORD

    ; Extern from Scheduler Harden
    extern Sovereign_Scheduler_Harden:PROC
    extern Sovereign_Scheduler_Release:PROC

    ; Transmission state
    current_gear    DWORD   1
    traction        BYTE    1
    hud_buffer      DB      256 DUP(0)

    GearStr         DB      "Gear: ",0
    PinStr          DB      " | Pin: ",0
    TpsStr          DB      " | TPS: ",0

.code
    extern Sovereign_Inflection_Feed:PROC
    extern ftoa_8:PROC
    extern itoa:PROC
    extern strcpy:PROC

    STATE_IDLE      EQU     0
    STATE_LAUNCH    EQU     1
    STATE_FLING     EQU     2
    STATE_GRAVITY   EQU     3

; -------------------------------------------------------------------
; Sovereign_Benchmark_Step
; Input:  xmm0 = measured TPS, xmm1 = token count (double)
; -------------------------------------------------------------------
Sovereign_Benchmark_Step PROC
    push    rbx
    push    rdi
    sub     rsp, 40h

    call    Sovereign_Inflection_Feed   ; rax=state, rdx=pin_point

    cmp     al, STATE_IDLE
    je      launch_mode
    cmp     al, STATE_LAUNCH
    je      traction_launch
    cmp     al, STATE_FLING
    je      upshift_4th
    cmp     al, STATE_GRAVITY
    je      latch_4th_block
    jmp     render_hud

launch_mode:
    mov     dword ptr [current_gear], 1
    mov     byte ptr [traction], 1
    sub     rsp, 20h
    call    Sovereign_Scheduler_Release
    add     rsp, 20h
    jmp     render_hud

traction_launch:
    mov     dword ptr [current_gear], 2
    mov     byte ptr [traction], 1
    jmp     render_hud

upshift_4th:
    mov     dword ptr [current_gear], 4
    mov     byte ptr [traction], 0
    jmp     render_hud

latch_4th_block:
    cmp     byte ptr [latch_4th], 0
    je      render_hud
    mov     dword ptr [current_gear], 4
    mov     byte ptr [traction], 0
    sub     rsp, 20h
    call    Sovereign_Scheduler_Harden
    add     rsp, 20h

render_hud:
    lea     rdi, [hud_buffer]

    lea     rcx, [GearStr]
    mov     rdx, rdi
    call    strcpy
    add     rdi, rax

    mov     eax, [current_gear]
    mov     rcx, rdi
    call    itoa
    add     rdi, rax

    lea     rcx, [PinStr]
    mov     rdx, rdi
    call    strcpy
    add     rdi, rax

    mov     eax, [pin_point]
    mov     rcx, rdi
    call    itoa
    add     rdi, rax

    lea     rcx, [TpsStr]
    mov     rdx, rdi
    call    strcpy
    add     rdi, rax

    mov     rcx, rdi
    call    ftoa_8

    add     rsp, 40h
    pop     rdi
    pop     rbx
    ret
Sovereign_Benchmark_Step ENDP

PUBLIC  Sovereign_Benchmark_Step
PUBLIC  current_gear
PUBLIC  hud_buffer

END