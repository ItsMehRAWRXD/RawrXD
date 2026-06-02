OPTION CASEMAP:NONE

PUBLIC obj_083_func
EXTERN obj_082_func:PROC
EXTERN obj_081_func:PROC

.code
obj_083_func PROC
    call obj_082_func
    call obj_081_func
    ret
obj_083_func ENDP

END
