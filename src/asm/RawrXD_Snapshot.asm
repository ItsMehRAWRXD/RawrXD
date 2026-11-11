OPTION CASEMAP:NONE
.code

; Snapshot exports
PUBLIC asm_snapshot_capture
PUBLIC asm_snapshot_restore
PUBLIC asm_snapshot_verify
PUBLIC asm_snapshot_discard
PUBLIC asm_snapshot_get_stats

asm_snapshot_capture PROC
    xor eax, eax
    ret
asm_snapshot_capture ENDP

asm_snapshot_restore PROC
    xor eax, eax
    ret
asm_snapshot_restore ENDP

asm_snapshot_verify PROC
    xor eax, eax
    ret
asm_snapshot_verify ENDP

asm_snapshot_discard PROC
    xor eax, eax
    ret
asm_snapshot_discard ENDP

asm_snapshot_get_stats PROC
    xor eax, eax
    ret
asm_snapshot_get_stats ENDP

END
