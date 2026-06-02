OPTION CASEMAP:NONE

PUBLIC obj_009_func
EXTERN obj_008_func:PROC
EXTERN obj_007_func:PROC

.code
obj_009_func PROC
    call obj_008_func
    call obj_007_func
    ret
obj_009_func ENDP

END
