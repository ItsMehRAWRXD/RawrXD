OPTION CASEMAP:NONE

PUBLIC obj_070_func
PUBLIC obj_070_dead
EXTERN obj_069_func:PROC
EXTERN obj_068_func:PROC

.code
obj_070_func PROC
    call obj_069_func
    call obj_068_func
    ret
obj_070_func ENDP

obj_070_dead PROC
    xor eax, eax
    ret
obj_070_dead ENDP

END
