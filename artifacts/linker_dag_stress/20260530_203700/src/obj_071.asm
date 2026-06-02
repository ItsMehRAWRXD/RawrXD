OPTION CASEMAP:NONE

PUBLIC obj_071_func
EXTERN obj_070_func:PROC
EXTERN obj_069_func:PROC

.code
obj_071_func PROC
    call obj_070_func
    call obj_069_func
    ret
obj_071_func ENDP

END
