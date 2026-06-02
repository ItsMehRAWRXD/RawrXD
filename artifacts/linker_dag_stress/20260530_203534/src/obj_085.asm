OPTION CASEMAP:NONE

PUBLIC obj_085_func
PUBLIC obj_085_dead
EXTERN obj_084_func:PROC
EXTERN obj_083_func:PROC

.code
obj_085_func PROC
    call obj_084_func
    call obj_083_func
    ret
obj_085_func ENDP

obj_085_dead PROC
    xor eax, eax
    ret
obj_085_dead ENDP

END
