OPTION CASEMAP:NONE

PUBLIC obj_127_func
EXTERN obj_126_func:PROC
EXTERN obj_125_func:PROC

.code
obj_127_func PROC
    call obj_126_func
    call obj_125_func
    ret
obj_127_func ENDP

END
