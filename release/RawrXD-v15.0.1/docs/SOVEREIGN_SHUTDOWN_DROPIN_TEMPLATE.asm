; SOVEREIGN_SHUTDOWN_DROPIN_TEMPLATE.asm
; Compact x64 MASM shutdown sequence adapted to SovereignOrchestrator style.
; Intended as a drop-in reference for worker/event/MMF lifecycle hardening.
;
; Preconditions:
; - Imports: SetEvent, WaitForSingleObject, CloseHandle, UnmapViewOfFile
; - Globals: g_Running, g_hInferenceTrigger, g_hCancelEvent, g_hInferenceThread,
;            g_hCmdEvent, g_hRespEvent, g_hShMem, g_pShMem
; - Optional: ResetBeaconHeader, OFF_SHUTDOWN_SENTINEL, SHUTDOWN_SENTINEL_CLEAN
;
; Order is deliberate:
; 1) stop signal, 2) wake blockers, 3) bounded thread drain, 4) scrub header,
; 5) close events, 6) unmap view, 7) close mapping.

BeaconCleanup_Template PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    sub rsp, 20h
    .allocstack 20h
    .endprolog

    ; 1) Global stop bit
    mov byte ptr [g_Running], 0

    ; 2) Wake any worker waits
    mov rcx, [g_hInferenceTrigger]
    test rcx, rcx
    jz short bc_skip_sig_infer
    call SetEvent
bc_skip_sig_infer:

    mov rcx, [g_hCancelEvent]
    test rcx, rcx
    jz short bc_skip_sig_cancel
    call SetEvent
bc_skip_sig_cancel:

    ; 3) Bounded drain for worker thread
    mov rcx, [g_hInferenceThread]
    test rcx, rcx
    jz short bc_skip_wait
    mov edx, 1000
    call WaitForSingleObject

    mov rcx, [g_hInferenceThread]
    test rcx, rcx
    jz short bc_skip_wait
    call CloseHandle
    mov qword ptr [g_hInferenceThread], 0
bc_skip_wait:

    ; 4) Scrub shared header and mark clean shutdown if desired
    call ResetBeaconHeader
    mov rbx, [g_pShMem]
    test rbx, rbx
    jz short bc_skip_sentinel
    mov rax, SHUTDOWN_SENTINEL_CLEAN
    mov qword ptr [rbx + OFF_SHUTDOWN_SENTINEL], rax
bc_skip_sentinel:

    ; 5) Close events
    mov rcx, [g_hInferenceTrigger]
    test rcx, rcx
    jz short bc_skip_close_infer
    call CloseHandle
bc_skip_close_infer:
    mov qword ptr [g_hInferenceTrigger], 0

    mov rcx, [g_hCancelEvent]
    test rcx, rcx
    jz short bc_skip_close_cancel
    call CloseHandle
bc_skip_close_cancel:
    mov qword ptr [g_hCancelEvent], 0

    mov rcx, [g_hCmdEvent]
    test rcx, rcx
    jz short bc_skip_close_cmd
    call CloseHandle
bc_skip_close_cmd:
    mov qword ptr [g_hCmdEvent], 0

    mov rcx, [g_hRespEvent]
    test rcx, rcx
    jz short bc_skip_close_resp
    call CloseHandle
bc_skip_close_resp:
    mov qword ptr [g_hRespEvent], 0

    ; 6) Unmap view before closing mapping handle
    mov rcx, [g_pShMem]
    test rcx, rcx
    jz short bc_skip_unmap
    call UnmapViewOfFile
bc_skip_unmap:
    mov qword ptr [g_pShMem], 0

    ; 7) Close mapping handle
    mov rcx, [g_hShMem]
    test rcx, rcx
    jz short bc_done
    call CloseHandle
bc_done:
    mov qword ptr [g_hShMem], 0

    leave
    ret
BeaconCleanup_Template ENDP
