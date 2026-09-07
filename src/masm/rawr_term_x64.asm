; rawr_term_x64.asm — tiny helper: RawrTermAliveProbe returns 1
OPTION CASEMAP:NONE
.code
PUBLIC RawrTermAliveProbe
RawrTermAliveProbe PROC
    mov eax, 1
    ret
RawrTermAliveProbe ENDP
END
