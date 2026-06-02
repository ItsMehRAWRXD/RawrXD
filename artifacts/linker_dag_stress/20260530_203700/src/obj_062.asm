OPTION CASEMAP:NONE

PUBLIC obj_062_func
EXTERN obj_061_func:PROC
EXTERN obj_060_func:PROC

.code
obj_062_func PROC
    call obj_061_func
    call obj_060_func
    ret
obj_062_func ENDP

END
