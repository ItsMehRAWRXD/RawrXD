OPTION CASEMAP:NONE

PUBLIC obj_107_func
EXTERN obj_106_func:PROC
EXTERN obj_105_func:PROC

.code
obj_107_func PROC
    call obj_106_func
    call obj_105_func
    ret
obj_107_func ENDP

END
