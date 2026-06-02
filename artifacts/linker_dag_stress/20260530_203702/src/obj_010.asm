OPTION CASEMAP:NONE

PUBLIC obj_010_func
PUBLIC obj_010_dead
EXTERN obj_009_func:PROC
EXTERN obj_008_func:PROC

.code
obj_010_func PROC
    call obj_009_func
    call obj_008_func
    ret
obj_010_func ENDP

obj_010_dead PROC
    xor eax, eax
    ret
obj_010_dead ENDP

END
