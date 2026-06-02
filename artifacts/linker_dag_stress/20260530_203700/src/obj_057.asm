OPTION CASEMAP:NONE

PUBLIC obj_057_func
EXTERN obj_056_func:PROC
EXTERN obj_055_func:PROC

.code
obj_057_func PROC
    call obj_056_func
    call obj_055_func
    ret
obj_057_func ENDP

END
