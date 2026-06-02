OPTION CASEMAP:NONE

PUBLIC obj_125_func
PUBLIC obj_125_dead
EXTERN obj_124_func:PROC
EXTERN obj_123_func:PROC

.code
obj_125_func PROC
    call obj_124_func
    call obj_123_func
    ret
obj_125_func ENDP

obj_125_dead PROC
    xor eax, eax
    ret
obj_125_dead ENDP

END
