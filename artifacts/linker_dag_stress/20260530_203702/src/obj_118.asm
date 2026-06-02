OPTION CASEMAP:NONE

PUBLIC obj_118_func
EXTERN obj_117_func:PROC
EXTERN obj_116_func:PROC

.code
obj_118_func PROC
    call obj_117_func
    call obj_116_func
    ret
obj_118_func ENDP

END
