OPTION CASEMAP:NONE

PUBLIC obj_012_func
EXTERN obj_011_func:PROC
EXTERN obj_010_func:PROC

.code
obj_012_func PROC
    call obj_011_func
    call obj_010_func
    ret
obj_012_func ENDP

END
