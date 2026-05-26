include Sovereign_Common.inc

.DATA
    ; Buffers remain local to this module's initialization logic
    ALIGN 16
    TPS_BUFFER   TPS_WORKSPACE <>
    GOV_BUFFER   GOV_STATE     <>
    MODEL_BUFFER MODEL_STATE   <>

.CODE
PUBLIC Sovereign_IPC_Bootstrap
Sovereign_IPC_Bootstrap PROC
    ; 1. Initialize TPS Workspace
    lea rax, TPS_BUFFER
    mov [g_pTPS], rax
    
    ; 2. Initialize Governance State
    lea rax, GOV_BUFFER
    mov [g_pGov], rax
    
    ; 3. Link Model State and Buffers
    lea rbx, MODEL_BUFFER
    mov [rax].GOV_STATE.pModelState, rbx
    
    lea rbx, TPS_BUFFER.logits
    mov [rax].GOV_STATE.pLogits, rbx
    
    lea rbx, TPS_BUFFER.token_ids
    mov [rax].GOV_STATE.pTokenBuffer, rbx
    
    ; 4. Set default parameters
    mov [rax].GOV_STATE.status, 0
    mov [eax].GOV_STATE.top_k, 40
    
    ret
Sovereign_IPC_Bootstrap ENDP
END
