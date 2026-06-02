OPTION CASEMAP:NONE

PUBLIC obj_011_func
EXTERN obj_010_func:PROC
EXTERN obj_009_func:PROC

.code
obj_011_func PROC
    call obj_010_func
    call obj_009_func
    ret
obj_011_func ENDP

END
