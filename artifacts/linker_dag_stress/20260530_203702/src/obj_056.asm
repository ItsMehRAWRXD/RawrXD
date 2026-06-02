OPTION CASEMAP:NONE

PUBLIC obj_056_func
EXTERN obj_055_func:PROC
EXTERN obj_054_func:PROC

.code
obj_056_func PROC
    call obj_055_func
    call obj_054_func
    ret
obj_056_func ENDP

END
