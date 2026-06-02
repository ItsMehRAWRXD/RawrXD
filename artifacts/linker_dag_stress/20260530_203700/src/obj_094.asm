OPTION CASEMAP:NONE

PUBLIC obj_094_func
EXTERN obj_093_func:PROC
EXTERN obj_092_func:PROC

.code
obj_094_func PROC
    call obj_093_func
    call obj_092_func
    ret
obj_094_func ENDP

END
