OPTION CASEMAP:NONE

PUBLIC obj_075_func
PUBLIC obj_075_dead
EXTERN obj_074_func:PROC
EXTERN obj_073_func:PROC

.code
obj_075_func PROC
    call obj_074_func
    call obj_073_func
    ret
obj_075_func ENDP

obj_075_dead PROC
    xor eax, eax
    ret
obj_075_dead ENDP

END
