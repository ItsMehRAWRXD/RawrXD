OPTION CASEMAP:NONE
MAX_ASSETS      equ 100
ENTRY_ACTIVE    equ 1
HOTPATCH_ENTRY STRUCT
    Status          dq 0
    pName           dq 0
    pCallback       dq 0
    LinkedArena     dq 0
HOTPATCH_ENTRY ENDS
GGUF_ENTRY STRUCT
    pBase           dq 0
    pName           dq 0
    Reserved1       dq 0
    Reserved2       dq 0
GGUF_ENTRY ENDS
SOVEREIGN_HUB STRUCT
    Signature           dq 0
    Patch_Registry      HOTPATCH_ENTRY MAX_ASSETS dup(<>)
    GGUF_Registry       GGUF_ENTRY MAX_ASSETS dup(<>)
SOVEREIGN_HUB ENDS
.DATA
    g_SovereignHub SOVEREIGN_HUB <>
    Titan_Peak_Cycles dq 0
    Titan_Peak_ID dq 0
    g_Apis dq 64 dup(0)
.CODE
Sovereign_Entry PROC
    lea r12, [g_SovereignHub]
    ret
Sovereign_Entry ENDP
END
