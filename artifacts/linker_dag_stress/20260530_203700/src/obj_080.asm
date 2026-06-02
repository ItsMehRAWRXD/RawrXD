OPTION CASEMAP:NONE

PUBLIC obj_080_func
PUBLIC obj_080_dead
EXTERN obj_079_func:PROC
EXTERN obj_078_func:PROC

.code
obj_080_func PROC
    call obj_079_func
    call obj_078_func
    ret
obj_080_func ENDP

obj_080_dead PROC
    xor eax, eax
    ret
obj_080_dead ENDP

END
