;================================================================================
; RawrXD_NetworkRelay.asm - Network relay kernel
;================================================================================
.code

PUBLIC NetworkRelay_Process
PUBLIC NetworkRelay_Emit

NetworkRelay_Process PROC
    xor eax, eax
    ret
NetworkRelay_Process ENDP

NetworkRelay_Emit PROC
    xor eax, eax
    ret
NetworkRelay_Emit ENDP

END