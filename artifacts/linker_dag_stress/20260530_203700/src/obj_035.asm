OPTION CASEMAP:NONE

PUBLIC obj_035_func
PUBLIC obj_035_dead
EXTERN obj_034_func:PROC
EXTERN obj_033_func:PROC

.code
obj_035_func PROC
    call obj_034_func
    call obj_033_func
    ret
obj_035_func ENDP

obj_035_dead PROC
    xor eax, eax
    ret
obj_035_dead ENDP

END
