OPTION CASEMAP:NONE

PUBLIC obj_036_func
EXTERN obj_035_func:PROC
EXTERN obj_034_func:PROC

.code
obj_036_func PROC
    call obj_035_func
    call obj_034_func
    ret
obj_036_func ENDP

END
