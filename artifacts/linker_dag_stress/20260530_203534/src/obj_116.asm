OPTION CASEMAP:NONE

PUBLIC obj_116_func
EXTERN obj_115_func:PROC
EXTERN obj_114_func:PROC

.code
obj_116_func PROC
    call obj_115_func
    call obj_114_func
    ret
obj_116_func ENDP

END
