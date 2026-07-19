OPTION CASEMAP:NONE
.code

; Hotpatch kernel exports
PUBLIC asm_hotpatch_flush_icache
PUBLIC asm_hotpatch_atomic_swap
PUBLIC asm_hotpatch_install_trampoline
PUBLIC asm_hotpatch_alloc_shadow
PUBLIC asm_hotpatch_free_shadow
PUBLIC asm_hotpatch_backup_prologue
PUBLIC asm_hotpatch_restore_prologue
PUBLIC asm_hotpatch_verify_prologue
PUBLIC asm_hotpatch_get_stats

; Stubs that return 0/false for now - real implementations needed
asm_hotpatch_flush_icache PROC
    xor eax, eax
    ret
asm_hotpatch_flush_icache ENDP

asm_hotpatch_atomic_swap PROC
    xor eax, eax
    ret
asm_hotpatch_atomic_swap ENDP

asm_hotpatch_install_trampoline PROC
    xor eax, eax
    ret
asm_hotpatch_install_trampoline ENDP

asm_hotpatch_alloc_shadow PROC
    xor eax, eax
    ret
asm_hotpatch_alloc_shadow ENDP

asm_hotpatch_free_shadow PROC
    xor eax, eax
    ret
asm_hotpatch_free_shadow ENDP

asm_hotpatch_backup_prologue PROC
    xor eax, eax
    ret
asm_hotpatch_backup_prologue ENDP

asm_hotpatch_restore_prologue PROC
    xor eax, eax
    ret
asm_hotpatch_restore_prologue ENDP

asm_hotpatch_verify_prologue PROC
    xor eax, eax
    ret
asm_hotpatch_verify_prologue ENDP

asm_hotpatch_get_stats PROC
    xor eax, eax
    ret
asm_hotpatch_get_stats ENDP

END
