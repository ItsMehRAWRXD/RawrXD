OPTION CASEMAP:NONE

PUBLIC obj_096_func
EXTERN obj_095_func:PROC
EXTERN obj_094_func:PROC

.code
obj_096_func PROC
    call obj_095_func
    call obj_094_func
    ret
obj_096_func ENDP

END
