OPTION CASEMAP:NONE

PUBLIC obj_044_func
EXTERN obj_043_func:PROC
EXTERN obj_042_func:PROC

.code
obj_044_func PROC
    call obj_043_func
    call obj_042_func
    ret
obj_044_func ENDP

END
