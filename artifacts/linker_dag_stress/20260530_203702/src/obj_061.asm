OPTION CASEMAP:NONE

PUBLIC obj_061_func
EXTERN obj_060_func:PROC
EXTERN obj_059_func:PROC

.code
obj_061_func PROC
    call obj_060_func
    call obj_059_func
    ret
obj_061_func ENDP

END
