OPTION CASEMAP:NONE

PUBLIC obj_040_func
PUBLIC obj_040_dead
EXTERN obj_039_func:PROC
EXTERN obj_038_func:PROC

.code
obj_040_func PROC
    call obj_039_func
    call obj_038_func
    ret
obj_040_func ENDP

obj_040_dead PROC
    xor eax, eax
    ret
obj_040_dead ENDP

END
