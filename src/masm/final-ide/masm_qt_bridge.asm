; ==========================================================================
; MASM Qt6 Component Conversion: Qt Bridge Layer (CLEAN)
; ==========================================================================

option casemap:none

include windows.inc
include masm_master_defs.inc

; External signal/slot functions from qt6_signal_slot_bridge.asm
EXTERN SignalSlot_Initialize:PROC
EXTERN SignalSlot_Connect:PROC
EXTERN SignalSlot_Disconnect:PROC
EXTERN SignalSlot_Emit:PROC

; External foundation functions
EXTERN qt_foundation_init:PROC
EXTERN process_events:PROC
EXTERN emit_signal:PROC

.data
    g_MasmBridgeInitialized BYTE 0
    g_QtCallbackAddr QWORD 0

.code

;==========================================================================
; FUNCTION: masm_qt_bridge_init
;==========================================================================
PUBLIC masm_qt_bridge_init
masm_qt_bridge_init PROC
    push rbx
    sub rsp, 32
    
    cmp g_MasmBridgeInitialized, 1
    je @L_already_init
    
    call qt_foundation_init
    call SignalSlot_Initialize
    
    mov g_MasmBridgeInitialized, 1
    
@L_already_init:
    mov eax, 1
    add rsp, 32
    pop rbx
    ret
masm_qt_bridge_init ENDP

;==========================================================================
; FUNCTION: masm_signal_connect
; RCX = signalId (DWORD)
; RDX = callbackAddr (QWORD)
;==========================================================================
PUBLIC masm_signal_connect
masm_signal_connect PROC
    push rbx
    sub rsp, 32
    
    ; Store the callback address (C++ side)
    mov g_QtCallbackAddr, rdx
    
    ; For now, we just return success. 
    ; In a full implementation, we'd register this in the SignalSlot manager.
    mov eax, 1
    
    add rsp, 32
    pop rbx
    ret
masm_signal_connect ENDP

;==========================================================================
; FUNCTION: masm_signal_disconnect
; RCX = signalId (DWORD)
;==========================================================================
PUBLIC masm_signal_disconnect
masm_signal_disconnect PROC
    mov eax, 1
    ret
masm_signal_disconnect ENDP

;==========================================================================
; FUNCTION: masm_signal_emit
; RCX = signalId (DWORD)
; RDX = paramCount (DWORD)
; R8 = params (Pointer to QtParam array)
;==========================================================================
PUBLIC masm_signal_emit
masm_signal_emit PROC
    push rbx
    sub rsp, 32
    
    ; RCX = signalId, RDX = paramCount, R8 = params
    ; We can forward this to SignalSlot_Emit or handle it directly.
    ; For now, return success.
    mov eax, 1
    
    add rsp, 32
    pop rbx
    ret
masm_signal_emit ENDP

;==========================================================================
; FUNCTION: masm_event_pump
;==========================================================================
PUBLIC masm_event_pump
masm_event_pump PROC
    push rbx
    sub rsp, 32
    
    call process_events
    
    add rsp, 32
    pop rbx
    ret
masm_event_pump ENDP

;==========================================================================
; FUNCTION: masm_emit_qt_signal
;==========================================================================
PUBLIC masm_emit_qt_signal
masm_emit_qt_signal PROC
    push rbx
    sub rsp, 32
    
    ; RCX = sender, RDX = signal_id, R8 = param
    call emit_signal
    
    add rsp, 32
    pop rbx
    ret
masm_emit_qt_signal ENDP

END
