OPTION CASEMAP:NONE

PUBLIC obj_023_func
EXTERN obj_022_func:PROC
EXTERN obj_021_func:PROC

.code
obj_023_func PROC
    call obj_022_func
    call obj_021_func
    ret
obj_023_func ENDP

END
