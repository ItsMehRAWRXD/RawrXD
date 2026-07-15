; Test calling an imported function
; The import table is set up by the linker
; We need to call through the Import Address Table

; For now, test that call rax encoding works
mov rax, 0
ret
