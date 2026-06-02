OPTION CASEMAP:NONE

PUBLIC obj_000_func
PUBLIC obj_000_dead

.code
obj_000_func PROC
    nop
    ret
obj_000_func ENDP

obj_000_dead PROC
    xor eax, eax
    ret
obj_000_dead ENDP

END
