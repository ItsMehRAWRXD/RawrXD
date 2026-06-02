OPTION CASEMAP:NONE

PUBLIC obj_026_func
EXTERN obj_025_func:PROC
EXTERN obj_024_func:PROC

.code
obj_026_func PROC
    call obj_025_func
    call obj_024_func
    ret
obj_026_func ENDP

END
