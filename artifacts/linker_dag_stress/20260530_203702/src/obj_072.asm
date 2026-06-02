OPTION CASEMAP:NONE

PUBLIC obj_072_func
EXTERN obj_071_func:PROC
EXTERN obj_070_func:PROC

.code
obj_072_func PROC
    call obj_071_func
    call obj_070_func
    ret
obj_072_func ENDP

END
