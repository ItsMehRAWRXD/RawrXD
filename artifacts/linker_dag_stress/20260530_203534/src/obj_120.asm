OPTION CASEMAP:NONE

PUBLIC obj_120_func
PUBLIC obj_120_dead
EXTERN obj_119_func:PROC
EXTERN obj_118_func:PROC

.code
obj_120_func PROC
    call obj_119_func
    call obj_118_func
    ret
obj_120_func ENDP

obj_120_dead PROC
    xor eax, eax
    ret
obj_120_dead ENDP

END
