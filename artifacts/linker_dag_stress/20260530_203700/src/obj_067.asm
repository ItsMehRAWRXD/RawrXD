OPTION CASEMAP:NONE

PUBLIC obj_067_func
EXTERN obj_066_func:PROC
EXTERN obj_065_func:PROC

.code
obj_067_func PROC
    call obj_066_func
    call obj_065_func
    ret
obj_067_func ENDP

END
