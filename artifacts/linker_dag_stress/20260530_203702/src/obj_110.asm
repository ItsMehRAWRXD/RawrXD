OPTION CASEMAP:NONE

PUBLIC obj_110_func
PUBLIC obj_110_dead
EXTERN obj_109_func:PROC
EXTERN obj_108_func:PROC

.code
obj_110_func PROC
    call obj_109_func
    call obj_108_func
    ret
obj_110_func ENDP

obj_110_dead PROC
    xor eax, eax
    ret
obj_110_dead ENDP

END
