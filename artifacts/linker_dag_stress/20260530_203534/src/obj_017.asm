OPTION CASEMAP:NONE

PUBLIC obj_017_func
EXTERN obj_016_func:PROC
EXTERN obj_015_func:PROC

.code
obj_017_func PROC
    call obj_016_func
    call obj_015_func
    ret
obj_017_func ENDP

END
