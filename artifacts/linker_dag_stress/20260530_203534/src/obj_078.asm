OPTION CASEMAP:NONE

PUBLIC obj_078_func
EXTERN obj_077_func:PROC
EXTERN obj_076_func:PROC

.code
obj_078_func PROC
    call obj_077_func
    call obj_076_func
    ret
obj_078_func ENDP

END
