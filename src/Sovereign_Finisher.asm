include Sovereign_Common.inc
extern g_ApiTable : SOVEREIGN_API_TABLE
extern Sovereign_Shutdown_Gameplay : PROC

.CODE
PUBLIC Sovereign_Shutdown_Final
Sovereign_Shutdown_Final PROC
    sub rsp, 40

    ; Call Gameplay Shutdown (Persistence)
    call Sovereign_Shutdown_Gameplay

    ; Clear sensitive buffers in TPS_BUFFER if necessary
    ; ...
    
    ; Call resolved ExitProcess
    xor rcx, rcx
    call [g_ApiTable.pExitProcess]
    
    add rsp, 40
    ret
Sovereign_Shutdown_Final ENDP
END
