OPTION CASEMAP:NONE

PUBLIC obj_030_func
PUBLIC obj_030_dead
EXTERN obj_029_func:PROC
EXTERN obj_028_func:PROC

.code
obj_030_func PROC
    call obj_029_func
    call obj_028_func
    ret
obj_030_func ENDP

obj_030_dead PROC
    xor eax, eax
    ret
obj_030_dead ENDP

END
