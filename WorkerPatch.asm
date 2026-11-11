; WorkerPatch.asm - Additional code to signal response event
; This should be linked with the worker to fix response signaling

OPTION CASEMAP:NONE

EXTERN g_hRespEvent : QWORD
EXTERN SetEvent : PROC

.CODE

; ----------------------------------------------------------------
; SignalResponseComplete - Signal the response event
; Call this after EnqueueAsyncResponse in the worker
; ----------------------------------------------------------------
SignalResponseComplete PROC EXPORT FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    sub rsp, 20h
    .allocstack 20h
    .endprolog

    mov rcx, [g_hRespEvent]
    test rcx, rcx
    jz signal_done
    call SetEvent

signal_done:
    xor eax, eax
    leave
    ret
SignalResponseComplete ENDP

END
