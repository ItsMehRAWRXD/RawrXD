OPTION CASEMAP:NONE

PUBLIC obj_060_func
PUBLIC obj_060_dead
EXTERN obj_059_func:PROC
EXTERN obj_058_func:PROC

.code
obj_060_func PROC
    call obj_059_func
    call obj_058_func
    ret
obj_060_func ENDP

obj_060_dead PROC
    xor eax, eax
    ret
obj_060_dead ENDP

END
