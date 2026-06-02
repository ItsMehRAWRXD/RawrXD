OPTION CASEMAP:NONE

PUBLIC obj_045_func
PUBLIC obj_045_dead
EXTERN obj_044_func:PROC
EXTERN obj_043_func:PROC

.code
obj_045_func PROC
    call obj_044_func
    call obj_043_func
    ret
obj_045_func ENDP

obj_045_dead PROC
    xor eax, eax
    ret
obj_045_dead ENDP

END
