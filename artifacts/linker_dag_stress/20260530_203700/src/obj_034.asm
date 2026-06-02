OPTION CASEMAP:NONE

PUBLIC obj_034_func
EXTERN obj_033_func:PROC
EXTERN obj_032_func:PROC

.code
obj_034_func PROC
    call obj_033_func
    call obj_032_func
    ret
obj_034_func ENDP

END
