OPTION CASEMAP:NONE

PUBLIC obj_003_func
EXTERN obj_002_func:PROC
EXTERN obj_001_func:PROC

.code
obj_003_func PROC
    call obj_002_func
    call obj_001_func
    ret
obj_003_func ENDP

END
