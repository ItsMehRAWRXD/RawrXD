OPTION CASEMAP:NONE

PUBLIC obj_115_func
PUBLIC obj_115_dead
EXTERN obj_114_func:PROC
EXTERN obj_113_func:PROC

.code
obj_115_func PROC
    call obj_114_func
    call obj_113_func
    ret
obj_115_func ENDP

obj_115_dead PROC
    xor eax, eax
    ret
obj_115_dead ENDP

END
