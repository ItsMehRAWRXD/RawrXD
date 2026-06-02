OPTION CASEMAP:NONE

PUBLIC obj_065_func
PUBLIC obj_065_dead
EXTERN obj_064_func:PROC
EXTERN obj_063_func:PROC

.code
obj_065_func PROC
    call obj_064_func
    call obj_063_func
    ret
obj_065_func ENDP

obj_065_dead PROC
    xor eax, eax
    ret
obj_065_dead ENDP

END
