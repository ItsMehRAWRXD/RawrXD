OPTION CASEMAP:NONE

PUBLIC obj_102_func
EXTERN obj_101_func:PROC
EXTERN obj_100_func:PROC

.code
obj_102_func PROC
    call obj_101_func
    call obj_100_func
    ret
obj_102_func ENDP

END
