OPTION CASEMAP:NONE

PUBLIC obj_113_func
EXTERN obj_112_func:PROC
EXTERN obj_111_func:PROC

.code
obj_113_func PROC
    call obj_112_func
    call obj_111_func
    ret
obj_113_func ENDP

END
