OPTION CASEMAP:NONE

PUBLIC obj_025_func
PUBLIC obj_025_dead
EXTERN obj_024_func:PROC
EXTERN obj_023_func:PROC

.code
obj_025_func PROC
    call obj_024_func
    call obj_023_func
    ret
obj_025_func ENDP

obj_025_dead PROC
    xor eax, eax
    ret
obj_025_dead ENDP

END
