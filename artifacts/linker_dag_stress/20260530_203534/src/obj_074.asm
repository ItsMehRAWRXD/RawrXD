OPTION CASEMAP:NONE

PUBLIC obj_074_func
EXTERN obj_073_func:PROC
EXTERN obj_072_func:PROC

.code
obj_074_func PROC
    call obj_073_func
    call obj_072_func
    ret
obj_074_func ENDP

END
