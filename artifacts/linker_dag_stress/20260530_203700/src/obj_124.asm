OPTION CASEMAP:NONE

PUBLIC obj_124_func
EXTERN obj_123_func:PROC
EXTERN obj_122_func:PROC

.code
obj_124_func PROC
    call obj_123_func
    call obj_122_func
    ret
obj_124_func ENDP

END
