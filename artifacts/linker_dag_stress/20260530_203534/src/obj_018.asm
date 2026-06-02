OPTION CASEMAP:NONE

PUBLIC obj_018_func
EXTERN obj_017_func:PROC
EXTERN obj_016_func:PROC

.code
obj_018_func PROC
    call obj_017_func
    call obj_016_func
    ret
obj_018_func ENDP

END
