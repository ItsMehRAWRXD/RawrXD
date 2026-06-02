OPTION CASEMAP:NONE

PUBLIC obj_091_func
EXTERN obj_090_func:PROC
EXTERN obj_089_func:PROC

.code
obj_091_func PROC
    call obj_090_func
    call obj_089_func
    ret
obj_091_func ENDP

END
