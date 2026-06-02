OPTION CASEMAP:NONE

PUBLIC obj_015_func
PUBLIC obj_015_dead
EXTERN obj_014_func:PROC
EXTERN obj_013_func:PROC

.code
obj_015_func PROC
    call obj_014_func
    call obj_013_func
    ret
obj_015_func ENDP

obj_015_dead PROC
    xor eax, eax
    ret
obj_015_dead ENDP

END
