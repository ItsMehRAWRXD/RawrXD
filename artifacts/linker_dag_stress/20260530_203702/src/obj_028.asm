OPTION CASEMAP:NONE

PUBLIC obj_028_func
EXTERN obj_027_func:PROC
EXTERN obj_026_func:PROC

.code
obj_028_func PROC
    call obj_027_func
    call obj_026_func
    ret
obj_028_func ENDP

END
