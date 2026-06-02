OPTION CASEMAP:NONE

PUBLIC obj_108_func
EXTERN obj_107_func:PROC
EXTERN obj_106_func:PROC

.code
obj_108_func PROC
    call obj_107_func
    call obj_106_func
    ret
obj_108_func ENDP

END
