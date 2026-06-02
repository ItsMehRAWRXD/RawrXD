OPTION CASEMAP:NONE

PUBLIC obj_109_func
EXTERN obj_108_func:PROC
EXTERN obj_107_func:PROC

.code
obj_109_func PROC
    call obj_108_func
    call obj_107_func
    ret
obj_109_func ENDP

END
