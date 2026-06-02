OPTION CASEMAP:NONE

PUBLIC obj_064_func
EXTERN obj_063_func:PROC
EXTERN obj_062_func:PROC

.code
obj_064_func PROC
    call obj_063_func
    call obj_062_func
    ret
obj_064_func ENDP

END
