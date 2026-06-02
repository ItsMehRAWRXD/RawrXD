OPTION CASEMAP:NONE

PUBLIC obj_019_func
EXTERN obj_018_func:PROC
EXTERN obj_017_func:PROC

.code
obj_019_func PROC
    call obj_018_func
    call obj_017_func
    ret
obj_019_func ENDP

END
