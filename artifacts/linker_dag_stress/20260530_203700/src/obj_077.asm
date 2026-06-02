OPTION CASEMAP:NONE

PUBLIC obj_077_func
EXTERN obj_076_func:PROC
EXTERN obj_075_func:PROC

.code
obj_077_func PROC
    call obj_076_func
    call obj_075_func
    ret
obj_077_func ENDP

END
