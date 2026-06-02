OPTION CASEMAP:NONE

PUBLIC obj_086_func
EXTERN obj_085_func:PROC
EXTERN obj_084_func:PROC

.code
obj_086_func PROC
    call obj_085_func
    call obj_084_func
    ret
obj_086_func ENDP

END
