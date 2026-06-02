OPTION CASEMAP:NONE

PUBLIC obj_047_func
EXTERN obj_046_func:PROC
EXTERN obj_045_func:PROC

.code
obj_047_func PROC
    call obj_046_func
    call obj_045_func
    ret
obj_047_func ENDP

END
