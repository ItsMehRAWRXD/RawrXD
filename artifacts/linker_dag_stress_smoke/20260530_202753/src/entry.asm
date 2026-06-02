OPTION CASEMAP:NONE

PUBLIC stress_entry
EXTERN obj_004_func:PROC
EXTERN obj_005_func:PROC

.code
stress_entry PROC
    call obj_004_func
    call obj_005_func
    xor eax, eax
    ret
stress_entry ENDP

END
