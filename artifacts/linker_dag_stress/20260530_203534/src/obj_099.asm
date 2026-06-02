OPTION CASEMAP:NONE

PUBLIC obj_099_func
EXTERN obj_098_func:PROC
EXTERN obj_097_func:PROC

.code
obj_099_func PROC
    call obj_098_func
    call obj_097_func
    ret
obj_099_func ENDP

END
