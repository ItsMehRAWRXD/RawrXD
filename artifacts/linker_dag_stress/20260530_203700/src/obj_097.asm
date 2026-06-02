OPTION CASEMAP:NONE

PUBLIC obj_097_func
EXTERN obj_096_func:PROC
EXTERN obj_095_func:PROC

.code
obj_097_func PROC
    call obj_096_func
    call obj_095_func
    ret
obj_097_func ENDP

END
