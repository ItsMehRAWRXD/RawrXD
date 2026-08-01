;; MASM Full Preprocessor Output
;; Source: test_masm_simple.asm

; Test MASM file for preprocessor
; Tests: EQU, INCLUDE (simulated), basic syntax

;; NULL EQU 0
;; TRUE EQU 1
;; FALSE EQU 0

.DATA

msg db "Hello", 0
value dd 0x12345678

.CODE

main PROC
    xor eax, eax
    mov eax, 1
    cmp eax, 0
    jne done
    
done:
    xor ecx, ecx
    ret

main ENDP

END
