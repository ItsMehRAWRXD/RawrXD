OPTION CASEMAP:NONE

PUBLIC obj_068_func
EXTERN obj_067_func:PROC
EXTERN obj_066_func:PROC

.code
obj_068_func PROC
    call obj_067_func
    call obj_066_func
    ret
obj_068_func ENDP

END
