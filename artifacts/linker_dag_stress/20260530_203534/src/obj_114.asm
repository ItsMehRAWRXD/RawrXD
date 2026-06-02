OPTION CASEMAP:NONE

PUBLIC obj_114_func
EXTERN obj_113_func:PROC
EXTERN obj_112_func:PROC

.code
obj_114_func PROC
    call obj_113_func
    call obj_112_func
    ret
obj_114_func ENDP

END
