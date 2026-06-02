OPTION CASEMAP:NONE

PUBLIC obj_007_func
EXTERN obj_006_func:PROC
EXTERN obj_005_func:PROC

.code
obj_007_func PROC
    call obj_006_func
    call obj_005_func
    ret
obj_007_func ENDP

END
