OPTION CASEMAP:NONE

PUBLIC obj_100_func
PUBLIC obj_100_dead
EXTERN obj_099_func:PROC
EXTERN obj_098_func:PROC

.code
obj_100_func PROC
    call obj_099_func
    call obj_098_func
    ret
obj_100_func ENDP

obj_100_dead PROC
    xor eax, eax
    ret
obj_100_dead ENDP

END
