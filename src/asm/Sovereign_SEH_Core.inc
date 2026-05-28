; ==================================================================================
; SOVEREIGN SEH CORE - UNWIND & FAILURE PARITY
; ==================================================================================

EXCEPTION_DATA STRUCT
    Begin   QWORD ?
    End     QWORD ?
    Handler QWORD ?
EXCEPTION_DATA ENDS

; ------------------------------
; FAILFAST HANDLER
; ------------------------------
FAIL_FAST MACRO code
    mov ecx, code
    int 3
    ud2
ENDM

; ------------------------------
; SAFE PROLOG ANCHOR
; ------------------------------
SEH_PROLOG MACRO label
    label:
    .allocstack 80h
    .pushreg rbp
ENDM

; ------------------------------
; UNWIND TABLE EMISSION
; ------------------------------
EMIT_UNWIND MACRO procname
    .pdata
    dq imagerel procname
    dq imagerel procname + 1
    dq imagerel procname
    .xdata
    db 01h, 04h, 02h, 00h
ENDM
