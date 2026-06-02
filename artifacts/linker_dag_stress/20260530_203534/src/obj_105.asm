OPTION CASEMAP:NONE

PUBLIC obj_105_func
PUBLIC obj_105_dead
EXTERN obj_104_func:PROC
EXTERN obj_103_func:PROC

.code
obj_105_func PROC
    call obj_104_func
    call obj_103_func
    ret
obj_105_func ENDP

obj_105_dead PROC
    xor eax, eax
    ret
obj_105_dead ENDP

END
