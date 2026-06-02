OPTION CASEMAP:NONE

PUBLIC obj_046_func
EXTERN obj_045_func:PROC
EXTERN obj_044_func:PROC

.code
obj_046_func PROC
    call obj_045_func
    call obj_044_func
    ret
obj_046_func ENDP

END
