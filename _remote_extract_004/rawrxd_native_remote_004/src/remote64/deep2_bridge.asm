OPTION CASEMAP:NONE
EXTERN RemoteAuthorityCanObserve:PROC
EXTERN RemoteAuthorityCanControl:PROC
PUBLIC Deep2RemoteObserveGate,Deep2RemoteControlGate
.code
Deep2RemoteObserveGate PROC
 sub rsp,28h
 call RemoteAuthorityCanObserve
 add rsp,28h
 test eax,eax
 jz dr_no
 xor eax,eax
 ret
dr_no: mov eax,-3
 ret
Deep2RemoteObserveGate ENDP
Deep2RemoteControlGate PROC
 sub rsp,28h
 call RemoteAuthorityCanControl
 add rsp,28h
 test eax,eax
 jz dc_no
 xor eax,eax
 ret
dc_no: mov eax,-3
 ret
Deep2RemoteControlGate ENDP
END
