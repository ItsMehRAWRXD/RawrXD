OPTION CASEMAP:NONE

PUBLIC obj_013_func
EXTERN obj_012_func:PROC
EXTERN obj_011_func:PROC

.code
obj_013_func PROC
    call obj_012_func
    call obj_011_func
    ret
obj_013_func ENDP

END
