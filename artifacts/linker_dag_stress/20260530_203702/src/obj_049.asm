OPTION CASEMAP:NONE

PUBLIC obj_049_func
EXTERN obj_048_func:PROC
EXTERN obj_047_func:PROC

.code
obj_049_func PROC
    call obj_048_func
    call obj_047_func
    ret
obj_049_func ENDP

END
