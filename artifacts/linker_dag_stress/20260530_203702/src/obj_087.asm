OPTION CASEMAP:NONE

PUBLIC obj_087_func
EXTERN obj_086_func:PROC
EXTERN obj_085_func:PROC

.code
obj_087_func PROC
    call obj_086_func
    call obj_085_func
    ret
obj_087_func ENDP

END
