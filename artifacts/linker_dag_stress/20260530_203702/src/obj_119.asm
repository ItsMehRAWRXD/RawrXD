OPTION CASEMAP:NONE

PUBLIC obj_119_func
EXTERN obj_118_func:PROC
EXTERN obj_117_func:PROC

.code
obj_119_func PROC
    call obj_118_func
    call obj_117_func
    ret
obj_119_func ENDP

END
