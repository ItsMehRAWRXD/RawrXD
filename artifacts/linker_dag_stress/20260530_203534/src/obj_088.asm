OPTION CASEMAP:NONE

PUBLIC obj_088_func
EXTERN obj_087_func:PROC
EXTERN obj_086_func:PROC

.code
obj_088_func PROC
    call obj_087_func
    call obj_086_func
    ret
obj_088_func ENDP

END
