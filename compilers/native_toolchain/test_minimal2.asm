; test_minimal2.asm - Minimal test function
; Build: ml64 /c /nologo test_minimal2.asm
; Link: gcc test_minimal2.obj test_minimal.c -o test_minimal2.exe

.code

test_minimal PROC
    mov eax, 1
    ret
test_minimal ENDP

PUBLIC test_minimal

END