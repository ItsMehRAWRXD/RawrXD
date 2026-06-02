OPTION CASEMAP:NONE

PUBLIC obj_095_func
PUBLIC obj_095_dead
EXTERN obj_094_func:PROC
EXTERN obj_093_func:PROC

.code
obj_095_func PROC
    call obj_094_func
    call obj_093_func
    ret
obj_095_func ENDP

obj_095_dead PROC
    xor eax, eax
    ret
obj_095_dead ENDP

END
