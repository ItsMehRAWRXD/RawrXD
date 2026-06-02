OPTION CASEMAP:NONE

PUBLIC obj_053_func
EXTERN obj_052_func:PROC
EXTERN obj_051_func:PROC

.code
obj_053_func PROC
    call obj_052_func
    call obj_051_func
    ret
obj_053_func ENDP

END
