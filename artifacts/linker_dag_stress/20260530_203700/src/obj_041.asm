OPTION CASEMAP:NONE

PUBLIC obj_041_func
EXTERN obj_040_func:PROC
EXTERN obj_039_func:PROC

.code
obj_041_func PROC
    call obj_040_func
    call obj_039_func
    ret
obj_041_func ENDP

END
