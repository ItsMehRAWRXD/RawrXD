OPTION CASEMAP:NONE

PUBLIC obj_005_func
EXTERN obj_004_func:PROC
EXTERN obj_003_func:PROC

.code
obj_005_func PROC
    call obj_004_func
    call obj_003_func
    ret
obj_005_func ENDP

END
