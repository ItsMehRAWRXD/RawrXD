OPTION CASEMAP:NONE

PUBLIC obj_029_func
EXTERN obj_028_func:PROC
EXTERN obj_027_func:PROC

.code
obj_029_func PROC
    call obj_028_func
    call obj_027_func
    ret
obj_029_func ENDP

END
