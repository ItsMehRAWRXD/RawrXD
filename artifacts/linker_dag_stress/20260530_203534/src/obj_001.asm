OPTION CASEMAP:NONE

PUBLIC obj_001_func
EXTERN obj_000_func:PROC

.code
obj_001_func PROC
    call obj_000_func
    ret
obj_001_func ENDP

END
