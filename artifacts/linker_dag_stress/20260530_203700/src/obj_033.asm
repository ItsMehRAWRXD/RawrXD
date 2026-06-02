OPTION CASEMAP:NONE

PUBLIC obj_033_func
EXTERN obj_032_func:PROC
EXTERN obj_031_func:PROC

.code
obj_033_func PROC
    call obj_032_func
    call obj_031_func
    ret
obj_033_func ENDP

END
