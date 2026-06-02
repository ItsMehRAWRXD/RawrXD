OPTION CASEMAP:NONE

PUBLIC obj_090_func
PUBLIC obj_090_dead
EXTERN obj_089_func:PROC
EXTERN obj_088_func:PROC

.code
obj_090_func PROC
    call obj_089_func
    call obj_088_func
    ret
obj_090_func ENDP

obj_090_dead PROC
    xor eax, eax
    ret
obj_090_dead ENDP

END
