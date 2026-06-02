OPTION CASEMAP:NONE

PUBLIC obj_004_func
EXTERN obj_003_func:PROC
EXTERN obj_002_func:PROC

.code
obj_004_func PROC
    call obj_003_func
    call obj_002_func
    ret
obj_004_func ENDP

END
