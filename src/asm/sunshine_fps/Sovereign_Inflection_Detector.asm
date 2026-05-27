; Sovereign_Inflection_Detector.asm
; x64 MASM — Zero Dependency — SSE2 Double-Precision
; Maintains rolling window of 3 samples, computes v and a in real-time

.data
    align 16
    ; Rolling history
    y_prev_prev     REAL8   0.0
    y_prev          REAL8   0.0
    t_prev_prev     REAL8   0.0
    t_prev          REAL8   0.0
    v_prev          REAL8   0.0
    a_prev          REAL8   0.0

    ; Thresholds
    FLING_THRESH    REAL8   1.0
    GRAVITY_THRESH  REAL8   -0.5
    DT_DEFAULT      REAL8   10.0
    ZERO_R8         REAL8   0.0
    POINT_ONE       REAL8   0.1
    POINT_FIVE      REAL8   0.5
    EPSILON         REAL8   1.0e-9

    ; State machine
    STATE_IDLE      EQU     0
    STATE_LAUNCH    EQU     1
    STATE_FLING     EQU     2
    STATE_GRAVITY   EQU     3
    current_state   DWORD   STATE_IDLE
    latch_4th       BYTE    0
    pin_point       DWORD   0

    ; Constants
    align 16
    Abs_Mask        DQ      7FFFFFFFFFFFFFFFh
                    DQ      7FFFFFFFFFFFFFFFh

.code

; -------------------------------------------------------------------
; Sovereign_Inflection_Feed
; Input:  xmm0 = current TPS, xmm1 = current token count (double)
; Output: rax = state code, rdx = pin_point token count
; -------------------------------------------------------------------
Sovereign_Inflection_Feed PROC
    sub     rsp, 58h                ; Shadow + align + locals

    ; Compute dt = t[i] - t[i-1]
    movsd   xmm2, xmm1              ; t[i]
    movsd   xmm5, qword ptr [t_prev]
    subsd   xmm2, xmm5              ; dt
    movsd   qword ptr [rsp+20h], xmm2

    ; Guard against division by zero (#DE)
    movsd   xmm7, qword ptr [EPSILON]
    comisd  xmm2, xmm7
    jb      skip_computation

    ; Compute v = (y[i] - y[i-1]) / dt
    movsd   xmm3, xmm0              ; y[i]
    movsd   xmm5, qword ptr [y_prev]
    subsd   xmm3, xmm5              ; dy
    divsd   xmm3, xmm2              ; v = dy/dt
    movsd   qword ptr [rsp+28h], xmm3

    ; Compute a = (v[i] - v[i-1]) / dt
    movsd   xmm4, xmm3
    movsd   xmm5, qword ptr [v_prev]
    subsd   xmm4, xmm5              ; dv
    divsd   xmm4, xmm2              ; a = dv/dt
    jmp     eval_states

skip_computation:
    xorpd   xmm3, xmm3              ; Zero v
    xorpd   xmm4, xmm4              ; Zero a

eval_states:
    ; --- State Machine ---
    mov     eax, [current_state]

    cmp     eax, STATE_IDLE
    je      check_launch

    cmp     eax, STATE_LAUNCH
    je      check_fling

    cmp     eax, STATE_FLING
    je      check_gravity

    cmp     eax, STATE_GRAVITY
    je      in_gravity

    jmp     update_history

check_launch:
    movsd   xmm5, xmm3
    andpd   xmm5, [Abs_Mask]
    movsd   xmm6, [POINT_ONE]
    comisd  xmm5, xmm6
    jb      update_history
    mov     eax, STATE_LAUNCH
    mov     [current_state], eax
    jmp     update_history

check_fling:
    movsd   xmm5, [FLING_THRESH]
    comisd  xmm4, xmm5
    jb      update_history
    mov     eax, STATE_FLING
    mov     [current_state], eax
    jmp     update_history

check_gravity:
    movsd   xmm5, [ZERO_R8]
    comisd  xmm4, xmm5
    jae     update_history
    ; Zero-crossing — latch pin point
    mov     eax, STATE_GRAVITY
    mov     [current_state], eax
    mov     byte ptr [latch_4th], 1
    cvtsd2si edx, [t_prev]
    mov     [pin_point], edx
    jmp     update_history

in_gravity:
    movsd   xmm5, [POINT_FIVE]
    comisd  xmm3, xmm5
    ja      update_history
    ; Velocity collapsed — reset
    mov     eax, STATE_IDLE
    mov     [current_state], eax
    mov     byte ptr [latch_4th], 0

update_history:
    ; Shift window
    movsd   xmm5, [y_prev]
    movsd   [y_prev_prev], xmm5
    movsd   [y_prev], xmm0
    movsd   xmm5, [t_prev]
    movsd   [t_prev_prev], xmm5
    movsd   [t_prev], xmm1
    movsd   [v_prev], xmm3
    movsd   [a_prev], xmm4

    ; Return
    mov     eax, [current_state]
    mov     edx, [pin_point]

    add     rsp, 58h
    ret
Sovereign_Inflection_Feed ENDP

; -------------------------------------------------------------------
; Sovereign_Inflection_Reset
; -------------------------------------------------------------------
Sovereign_Inflection_Reset PROC
    mov     dword ptr [current_state], STATE_IDLE
    mov     byte ptr [latch_4th], 0
    mov     dword ptr [pin_point], 0
    xorpd   xmm0, xmm0              ; Zero-latency clear
    movsd   [y_prev_prev], xmm0
    movsd   [y_prev], xmm0
    movsd   [v_prev], xmm0
    movsd   [a_prev], xmm0
    ret
Sovereign_Inflection_Reset ENDP

PUBLIC  Sovereign_Inflection_Feed
PUBLIC  Sovereign_Inflection_Reset
PUBLIC  current_state
PUBLIC  latch_4th
PUBLIC  pin_point
PUBLIC  y_prev
PUBLIC  t_prev
PUBLIC  v_prev

END