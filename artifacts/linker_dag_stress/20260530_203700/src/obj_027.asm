OPTION CASEMAP:NONE

PUBLIC obj_027_func
EXTERN obj_026_func:PROC
EXTERN obj_025_func:PROC

.code
obj_027_func PROC
    call obj_026_func
    call obj_025_func
    ret
obj_027_func ENDP

END
