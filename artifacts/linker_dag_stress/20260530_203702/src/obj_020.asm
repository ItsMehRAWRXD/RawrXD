OPTION CASEMAP:NONE

PUBLIC obj_020_func
PUBLIC obj_020_dead
EXTERN obj_019_func:PROC
EXTERN obj_018_func:PROC

.code
obj_020_func PROC
    call obj_019_func
    call obj_018_func
    ret
obj_020_func ENDP

obj_020_dead PROC
    xor eax, eax
    ret
obj_020_dead ENDP

END
