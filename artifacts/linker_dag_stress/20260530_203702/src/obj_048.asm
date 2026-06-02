OPTION CASEMAP:NONE

PUBLIC obj_048_func
EXTERN obj_047_func:PROC
EXTERN obj_046_func:PROC

.code
obj_048_func PROC
    call obj_047_func
    call obj_046_func
    ret
obj_048_func ENDP

END
