OPTION CASEMAP:NONE

PUBLIC obj_123_func
EXTERN obj_122_func:PROC
EXTERN obj_121_func:PROC

.code
obj_123_func PROC
    call obj_122_func
    call obj_121_func
    ret
obj_123_func ENDP

END
