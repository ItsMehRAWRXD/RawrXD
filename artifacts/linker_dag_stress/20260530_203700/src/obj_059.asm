OPTION CASEMAP:NONE

PUBLIC obj_059_func
EXTERN obj_058_func:PROC
EXTERN obj_057_func:PROC

.code
obj_059_func PROC
    call obj_058_func
    call obj_057_func
    ret
obj_059_func ENDP

END
