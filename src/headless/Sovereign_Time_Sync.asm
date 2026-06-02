; =========================================================================================
; SOVEREIGN TIME SYNC
; High-resolution system clock polling terminal interfaces.
; Prevents multi-core temporal drift from affecting step-rate determinism.
; =========================================================================================

OPTION CASEMAP:NONE

EXTERN QueryPerformanceFrequency:PROC
EXTERN QueryPerformanceCounter:PROC

PUBLIC XR_Time_Initialize
PUBLIC XR_Time_Query_Interval
PUBLIC g_Clock_Frequency
PUBLIC g_Time_Baseline_Tick
PUBLIC g_Time_Current_Tick
PUBLIC g_Microseconds_Delta

.DATA
    ALIGN 8
    g_Clock_Frequency    dq 0
    g_Time_Baseline_Tick dq 0
    g_Time_Current_Tick  dq 0
    g_Microseconds_Delta dq 0

.CODE

; -----------------------------------------------------------------------------------------
; XR_Time_Initialize
; Returns RAX = initialization status (1 = clock ready, 0 = host timer failure)
; -----------------------------------------------------------------------------------------
ALIGN 16
XR_Time_Initialize PROC
    sub rsp, 28h

    lea rcx, g_Clock_Frequency
    call QueryPerformanceFrequency
    test eax, eax
    jz @@time_init_fail

    lea rcx, g_Time_Baseline_Tick
    call QueryPerformanceCounter
    test eax, eax
    jz @@time_init_fail

    mov eax, 1
    add rsp, 28h
    ret

@@time_init_fail:
    xor eax, eax
    mov [g_Clock_Frequency], rax
    mov [g_Time_Baseline_Tick], rax
    add rsp, 28h
    ret
XR_Time_Initialize ENDP

; -----------------------------------------------------------------------------------------
; XR_Time_Query_Interval
; Returns RAX = exact microsecond integer elapsed time since the previous baseline tick.
; -----------------------------------------------------------------------------------------
ALIGN 16
XR_Time_Query_Interval PROC
    sub rsp, 28h

    lea rcx, g_Time_Current_Tick
    call QueryPerformanceCounter
    test eax, eax
    jz @@time_query_fail

    mov rcx, [g_Clock_Frequency]
    test rcx, rcx
    jz @@time_query_fail

    mov rax, [g_Time_Current_Tick]
    sub rax, [g_Time_Baseline_Tick]
    mov r8, 1000000
    mul r8
    div rcx

    mov [g_Microseconds_Delta], rax
    mov rcx, [g_Time_Current_Tick]
    mov [g_Time_Baseline_Tick], rcx

    add rsp, 28h
    ret

@@time_query_fail:
    xor eax, eax
    mov [g_Microseconds_Delta], rax
    add rsp, 28h
    ret
XR_Time_Query_Interval ENDP

END