OPTION CASEMAP:NONE

PUBLIC obj_082_func
EXTERN obj_081_func:PROC
EXTERN obj_080_func:PROC

.code
obj_082_func PROC
    call obj_081_func
    call obj_080_func
    ret
obj_082_func ENDP

END
