OPTION CASEMAP:NONE

PUBLIC obj_069_func
EXTERN obj_068_func:PROC
EXTERN obj_067_func:PROC

.code
obj_069_func PROC
    call obj_068_func
    call obj_067_func
    ret
obj_069_func ENDP

END
