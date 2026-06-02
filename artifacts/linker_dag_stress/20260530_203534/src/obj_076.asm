OPTION CASEMAP:NONE

PUBLIC obj_076_func
EXTERN obj_075_func:PROC
EXTERN obj_074_func:PROC

.code
obj_076_func PROC
    call obj_075_func
    call obj_074_func
    ret
obj_076_func ENDP

END
