OPTION CASEMAP:NONE

PUBLIC obj_104_func
EXTERN obj_103_func:PROC
EXTERN obj_102_func:PROC

.code
obj_104_func PROC
    call obj_103_func
    call obj_102_func
    ret
obj_104_func ENDP

END
