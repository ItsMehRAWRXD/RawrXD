; ==============================================================================
; SimpleTest.asm - Simple test with correct Windows x64 calling convention
; ==============================================================================

.code

SimpleTest PROC
    ; No prologue/epilogue - just return
    ret
SimpleTest ENDP

END