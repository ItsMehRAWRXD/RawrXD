OPTION CASEMAP:NONE

PUBLIC obj_126_func
EXTERN obj_125_func:PROC
EXTERN obj_124_func:PROC

.code
obj_126_func PROC
    call obj_125_func
    call obj_124_func
    ret
obj_126_func ENDP

END
