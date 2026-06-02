OPTION CASEMAP:NONE

PUBLIC obj_063_func
EXTERN obj_062_func:PROC
EXTERN obj_061_func:PROC

.code
obj_063_func PROC
    call obj_062_func
    call obj_061_func
    ret
obj_063_func ENDP

END
