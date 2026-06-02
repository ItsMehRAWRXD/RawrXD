OPTION CASEMAP:NONE

PUBLIC obj_031_func
EXTERN obj_030_func:PROC
EXTERN obj_029_func:PROC

.code
obj_031_func PROC
    call obj_030_func
    call obj_029_func
    ret
obj_031_func ENDP

END
