OPTION CASEMAP:NONE

PUBLIC obj_122_func
EXTERN obj_121_func:PROC
EXTERN obj_120_func:PROC

.code
obj_122_func PROC
    call obj_121_func
    call obj_120_func
    ret
obj_122_func ENDP

END
