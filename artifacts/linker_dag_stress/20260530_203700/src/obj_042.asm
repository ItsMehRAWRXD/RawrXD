OPTION CASEMAP:NONE

PUBLIC obj_042_func
EXTERN obj_041_func:PROC
EXTERN obj_040_func:PROC

.code
obj_042_func PROC
    call obj_041_func
    call obj_040_func
    ret
obj_042_func ENDP

END
