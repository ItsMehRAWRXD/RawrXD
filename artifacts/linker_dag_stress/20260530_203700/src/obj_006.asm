OPTION CASEMAP:NONE

PUBLIC obj_006_func
EXTERN obj_005_func:PROC
EXTERN obj_004_func:PROC

.code
obj_006_func PROC
    call obj_005_func
    call obj_004_func
    ret
obj_006_func ENDP

END
