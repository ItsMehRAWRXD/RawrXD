OPTION CASEMAP:NONE

PUBLIC obj_008_func
EXTERN obj_007_func:PROC
EXTERN obj_006_func:PROC

.code
obj_008_func PROC
    call obj_007_func
    call obj_006_func
    ret
obj_008_func ENDP

END
