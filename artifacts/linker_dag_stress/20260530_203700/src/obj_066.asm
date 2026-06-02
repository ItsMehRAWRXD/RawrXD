OPTION CASEMAP:NONE

PUBLIC obj_066_func
EXTERN obj_065_func:PROC
EXTERN obj_064_func:PROC

.code
obj_066_func PROC
    call obj_065_func
    call obj_064_func
    ret
obj_066_func ENDP

END
