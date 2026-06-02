OPTION CASEMAP:NONE

PUBLIC obj_016_func
EXTERN obj_015_func:PROC
EXTERN obj_014_func:PROC

.code
obj_016_func PROC
    call obj_015_func
    call obj_014_func
    ret
obj_016_func ENDP

END
