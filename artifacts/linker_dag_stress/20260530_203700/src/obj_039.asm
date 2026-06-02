OPTION CASEMAP:NONE

PUBLIC obj_039_func
EXTERN obj_038_func:PROC
EXTERN obj_037_func:PROC

.code
obj_039_func PROC
    call obj_038_func
    call obj_037_func
    ret
obj_039_func ENDP

END
