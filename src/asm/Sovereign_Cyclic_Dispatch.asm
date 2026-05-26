include Sovereign_Common.inc
EXTERN Sovereign_Registry_Step_Lean : PROC
.CODE
PUBLIC Sovereign_Kernel_MainLoop
Sovereign_Kernel_MainLoop PROC
@@Retry:
    call Sovereign_Registry_Step_Lean
    jmp @@Retry
Sovereign_Kernel_MainLoop ENDP
END
