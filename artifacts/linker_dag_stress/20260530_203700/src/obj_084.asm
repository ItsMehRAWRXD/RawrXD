OPTION CASEMAP:NONE

PUBLIC obj_084_func
EXTERN obj_083_func:PROC
EXTERN obj_082_func:PROC

.code
obj_084_func PROC
    call obj_083_func
    call obj_082_func
    ret
obj_084_func ENDP

END
