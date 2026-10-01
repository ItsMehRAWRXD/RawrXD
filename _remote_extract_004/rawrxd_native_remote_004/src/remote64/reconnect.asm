OPTION CASEMAP:NONE
PUBLIC RemoteReconnect_NextDelay
.code
RemoteReconnect_NextDelay PROC
    ; ecx=attempt -> eax milliseconds, capped 30s
    mov eax,250
    test ecx,ecx
    jz rr_done
rr_loop:
    cmp eax,30000
    jae rr_cap
    shl eax,1
    dec ecx
    jnz rr_loop
    cmp eax,30000
    jbe rr_done
rr_cap:
    mov eax,30000
rr_done:
    ret
RemoteReconnect_NextDelay ENDP
END
