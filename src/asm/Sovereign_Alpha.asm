OPTION CASEMAP:NONE
MAX_ASSETS equ 100
HOTPATCH_ENTRY STRUCT
    Status          dq 0
    pName           dq 0
    pCallback       dq 0
    LinkedArena     dq 0
HOTPATCH_ENTRY ENDS
.DATA
    g_Hub HOTPATCH_ENTRY MAX_ASSETS dup(<>)
.CODE
Sovereign_Alpha_Entry PROC
    lea r12, [g_Hub]
    ret
Sovereign_Alpha_Entry ENDP
END
