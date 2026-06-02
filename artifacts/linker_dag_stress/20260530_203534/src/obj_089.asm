OPTION CASEMAP:NONE

PUBLIC obj_089_func
EXTERN obj_088_func:PROC
EXTERN obj_087_func:PROC

.code
obj_089_func PROC
    call obj_088_func
    call obj_087_func
    ret
obj_089_func ENDP

END
