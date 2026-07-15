; UltraMinimal.asm - No external calls except ExitProcess
option casemap:none

EXTERNDEF ExitProcess:PROC

.data
    dummy dq 0

.code

PUBLIC mainCRTStartup

mainCRTStartup PROC
    xor     ecx, ecx
    call    ExitProcess
    ret
mainCRTStartup ENDP
END
