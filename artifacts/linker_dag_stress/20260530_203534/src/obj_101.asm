OPTION CASEMAP:NONE

PUBLIC obj_101_func
EXTERN obj_100_func:PROC
EXTERN obj_099_func:PROC

.code
obj_101_func PROC
    call obj_100_func
    call obj_099_func
    ret
obj_101_func ENDP

END
