OPTION CASEMAP:NONE

PUBLIC obj_051_func
EXTERN obj_050_func:PROC
EXTERN obj_049_func:PROC

.code
obj_051_func PROC
    call obj_050_func
    call obj_049_func
    ret
obj_051_func ENDP

END
