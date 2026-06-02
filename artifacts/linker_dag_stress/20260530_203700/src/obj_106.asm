OPTION CASEMAP:NONE

PUBLIC obj_106_func
EXTERN obj_105_func:PROC
EXTERN obj_104_func:PROC

.code
obj_106_func PROC
    call obj_105_func
    call obj_104_func
    ret
obj_106_func ENDP

END
