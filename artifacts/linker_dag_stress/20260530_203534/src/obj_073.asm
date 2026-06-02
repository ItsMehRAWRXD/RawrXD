OPTION CASEMAP:NONE

PUBLIC obj_073_func
EXTERN obj_072_func:PROC
EXTERN obj_071_func:PROC

.code
obj_073_func PROC
    call obj_072_func
    call obj_071_func
    ret
obj_073_func ENDP

END
