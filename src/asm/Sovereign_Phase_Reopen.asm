; Sovereign_Phase_Reopen.asm — GATE STOP forces attribution-only (§16)
; PROMOTE always written 0 on draft/auxiliary receipts.
PUBLIC Draft_Latency_Split_Receipt
PUBLIC g_Gate_Status
PUBLIC g_Receipt_Promote
PUBLIC g_Readback_Reduced

EXTERN Allocate_Registry_Slot:PROC

.data
ALIGN 8
g_Gate_Status       dq 1    ; bit0=STOP (default sealed)
g_Receipt_Promote   dq 0
g_Readback_Reduced  dq 0

.code
; Enforces adjudication: STOP=1 => PROMOTE=0, READBACK_REDUCED draft=0
; Returns RAX=0 always (draft never promotes under STOP).
Draft_Latency_Split_Receipt PROC
    push rbx
    sub  rsp, 28h
    mov  rax, [g_Gate_Status]
    and  rax, 1
    jnz  GateStopEnforced
    ; Phase-reopen cleared: still draft — PROMOTE=0 per completion contract
    mov  qword ptr [g_Receipt_Promote], 0
    ; U-tier inventory signature only; no champion rewrite
    mov  rcx, COMP_UTIER_TRACE
    call Allocate_Registry_Slot
    jmp  Exit
GateStopEnforced:
    mov  qword ptr [g_Receipt_Promote], 0
    mov  qword ptr [g_Readback_Reduced], 0
Exit:
    xor  rax, rax
    add  rsp, 28h
    pop  rbx
    ret
Draft_Latency_Split_Receipt ENDP

END
