OPTION CASEMAP:NONE

PUBLIC obj_043_func
EXTERN obj_042_func:PROC
EXTERN obj_041_func:PROC

.code
obj_043_func PROC
    call obj_042_func
    call obj_041_func
    ret
obj_043_func ENDP

END
