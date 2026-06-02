OPTION CASEMAP:NONE

PUBLIC obj_021_func
EXTERN obj_020_func:PROC
EXTERN obj_019_func:PROC

.code
obj_021_func PROC
    call obj_020_func
    call obj_019_func
    ret
obj_021_func ENDP

END
