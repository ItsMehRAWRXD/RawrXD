OPTION CASEMAP:NONE

PUBLIC obj_002_func
EXTERN obj_001_func:PROC
EXTERN obj_000_func:PROC

.code
obj_002_func PROC
    call obj_001_func
    call obj_000_func
    ret
obj_002_func ENDP

END
