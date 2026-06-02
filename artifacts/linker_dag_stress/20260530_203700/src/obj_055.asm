OPTION CASEMAP:NONE

PUBLIC obj_055_func
PUBLIC obj_055_dead
EXTERN obj_054_func:PROC
EXTERN obj_053_func:PROC

.code
obj_055_func PROC
    call obj_054_func
    call obj_053_func
    ret
obj_055_func ENDP

obj_055_dead PROC
    xor eax, eax
    ret
obj_055_dead ENDP

END
