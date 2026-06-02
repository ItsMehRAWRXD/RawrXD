OPTION CASEMAP:NONE

PUBLIC obj_093_func
EXTERN obj_092_func:PROC
EXTERN obj_091_func:PROC

.code
obj_093_func PROC
    call obj_092_func
    call obj_091_func
    ret
obj_093_func ENDP

END
