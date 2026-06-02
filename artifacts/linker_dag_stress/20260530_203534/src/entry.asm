OPTION CASEMAP:NONE

PUBLIC stress_entry
EXTERN obj_126_func:PROC
EXTERN obj_127_func:PROC

.code
stress_entry PROC
    call obj_126_func
    call obj_127_func
    xor eax, eax
    ret
stress_entry ENDP

END
