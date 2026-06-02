OPTION CASEMAP:NONE

PUBLIC obj_032_func
EXTERN obj_031_func:PROC
EXTERN obj_030_func:PROC

.code
obj_032_func PROC
    call obj_031_func
    call obj_030_func
    ret
obj_032_func ENDP

END
