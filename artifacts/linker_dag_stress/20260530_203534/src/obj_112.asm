OPTION CASEMAP:NONE

PUBLIC obj_112_func
EXTERN obj_111_func:PROC
EXTERN obj_110_func:PROC

.code
obj_112_func PROC
    call obj_111_func
    call obj_110_func
    ret
obj_112_func ENDP

END
