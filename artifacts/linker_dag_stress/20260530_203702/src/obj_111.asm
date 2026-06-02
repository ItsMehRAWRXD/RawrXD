OPTION CASEMAP:NONE

PUBLIC obj_111_func
EXTERN obj_110_func:PROC
EXTERN obj_109_func:PROC

.code
obj_111_func PROC
    call obj_110_func
    call obj_109_func
    ret
obj_111_func ENDP

END
