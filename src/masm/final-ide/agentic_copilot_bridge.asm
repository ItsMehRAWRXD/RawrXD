; ==========================================================================
; MASM Agentic Copilot Bridge (CLEAN)
; ==========================================================================

option casemap:none

include windows.inc
include masm_master_defs.inc

; External functions
EXTERN agent_coordinator_init:PROC
EXTERN agent_coordinator_shutdown:PROC

.code

;==========================================================================
; FUNCTION: copilot_bridge_init
;==========================================================================
PUBLIC copilot_bridge_init
copilot_bridge_init PROC
    push rbx
    sub rsp, 32
    
    call agent_coordinator_init
    
    xor rax, rax
    add rsp, 32
    pop rbx
    ret
copilot_bridge_init ENDP

;==========================================================================
; FUNCTION: copilot_bridge_shutdown
;==========================================================================
PUBLIC copilot_bridge_shutdown
copilot_bridge_shutdown PROC
    push rbx
    sub rsp, 32
    
    call agent_coordinator_shutdown
    
    add rsp, 32
    pop rbx
    ret
copilot_bridge_shutdown ENDP

END
