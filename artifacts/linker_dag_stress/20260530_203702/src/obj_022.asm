OPTION CASEMAP:NONE

PUBLIC obj_022_func
EXTERN obj_021_func:PROC
EXTERN obj_020_func:PROC

.code
obj_022_func PROC
    call obj_021_func
    call obj_020_func
    ret
obj_022_func ENDP

END
