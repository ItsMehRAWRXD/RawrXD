OPTION CASEMAP:NONE

PUBLIC obj_117_func
EXTERN obj_116_func:PROC
EXTERN obj_115_func:PROC

.code
obj_117_func PROC
    call obj_116_func
    call obj_115_func
    ret
obj_117_func ENDP

END
