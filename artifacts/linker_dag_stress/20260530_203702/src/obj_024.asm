OPTION CASEMAP:NONE

PUBLIC obj_024_func
EXTERN obj_023_func:PROC
EXTERN obj_022_func:PROC

.code
obj_024_func PROC
    call obj_023_func
    call obj_022_func
    ret
obj_024_func ENDP

END
