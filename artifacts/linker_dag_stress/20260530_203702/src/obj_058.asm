OPTION CASEMAP:NONE

PUBLIC obj_058_func
EXTERN obj_057_func:PROC
EXTERN obj_056_func:PROC

.code
obj_058_func PROC
    call obj_057_func
    call obj_056_func
    ret
obj_058_func ENDP

END
