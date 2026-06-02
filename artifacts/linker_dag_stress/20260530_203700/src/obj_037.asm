OPTION CASEMAP:NONE

PUBLIC obj_037_func
EXTERN obj_036_func:PROC
EXTERN obj_035_func:PROC

.code
obj_037_func PROC
    call obj_036_func
    call obj_035_func
    ret
obj_037_func ENDP

END
