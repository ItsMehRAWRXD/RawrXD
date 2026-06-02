OPTION CASEMAP:NONE

PUBLIC obj_103_func
EXTERN obj_102_func:PROC
EXTERN obj_101_func:PROC

.code
obj_103_func PROC
    call obj_102_func
    call obj_101_func
    ret
obj_103_func ENDP

END
