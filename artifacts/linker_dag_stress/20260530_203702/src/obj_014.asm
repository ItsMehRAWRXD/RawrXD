OPTION CASEMAP:NONE

PUBLIC obj_014_func
EXTERN obj_013_func:PROC
EXTERN obj_012_func:PROC

.code
obj_014_func PROC
    call obj_013_func
    call obj_012_func
    ret
obj_014_func ENDP

END
