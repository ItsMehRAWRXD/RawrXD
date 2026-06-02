OPTION CASEMAP:NONE

PUBLIC obj_054_func
EXTERN obj_053_func:PROC
EXTERN obj_052_func:PROC

.code
obj_054_func PROC
    call obj_053_func
    call obj_052_func
    ret
obj_054_func ENDP

END
