OPTION CASEMAP:NONE

PUBLIC obj_092_func
EXTERN obj_091_func:PROC
EXTERN obj_090_func:PROC

.code
obj_092_func PROC
    call obj_091_func
    call obj_090_func
    ret
obj_092_func ENDP

END
