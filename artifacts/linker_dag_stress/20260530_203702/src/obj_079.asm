OPTION CASEMAP:NONE

PUBLIC obj_079_func
EXTERN obj_078_func:PROC
EXTERN obj_077_func:PROC

.code
obj_079_func PROC
    call obj_078_func
    call obj_077_func
    ret
obj_079_func ENDP

END
