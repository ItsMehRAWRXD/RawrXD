OPTION CASEMAP:NONE

PUBLIC obj_081_func
EXTERN obj_080_func:PROC
EXTERN obj_079_func:PROC

.code
obj_081_func PROC
    call obj_080_func
    call obj_079_func
    ret
obj_081_func ENDP

END
