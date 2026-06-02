OPTION CASEMAP:NONE

PUBLIC obj_038_func
EXTERN obj_037_func:PROC
EXTERN obj_036_func:PROC

.code
obj_038_func PROC
    call obj_037_func
    call obj_036_func
    ret
obj_038_func ENDP

END
