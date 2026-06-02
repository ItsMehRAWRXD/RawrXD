OPTION CASEMAP:NONE

PUBLIC obj_098_func
EXTERN obj_097_func:PROC
EXTERN obj_096_func:PROC

.code
obj_098_func PROC
    call obj_097_func
    call obj_096_func
    ret
obj_098_func ENDP

END
