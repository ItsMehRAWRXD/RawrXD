OPTION CASEMAP:NONE

PUBLIC obj_052_func
EXTERN obj_051_func:PROC
EXTERN obj_050_func:PROC

.code
obj_052_func PROC
    call obj_051_func
    call obj_050_func
    ret
obj_052_func ENDP

END
