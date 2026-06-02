OPTION CASEMAP:NONE

PUBLIC obj_050_func
PUBLIC obj_050_dead
EXTERN obj_049_func:PROC
EXTERN obj_048_func:PROC

.code
obj_050_func PROC
    call obj_049_func
    call obj_048_func
    ret
obj_050_func ENDP

obj_050_dead PROC
    xor eax, eax
    ret
obj_050_dead ENDP

END
