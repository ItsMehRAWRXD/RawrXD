OPTION CASEMAP:NONE

PUBLIC obj_121_func
EXTERN obj_120_func:PROC
EXTERN obj_119_func:PROC

.code
obj_121_func PROC
    call obj_120_func
    call obj_119_func
    ret
obj_121_func ENDP

END
