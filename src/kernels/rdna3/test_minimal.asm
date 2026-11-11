; test_minimal.asm
; Minimal test to verify build pipeline

.data
ALIGN 8

PUBLIC test_data
test_data LABEL BYTE
    DB 064h, 086h, 001h, 000h, 000h, 000h, 000h, 000h
    DB 001h, 010h, 000h, 000h, 000h, 000h, 000h, 000h
test_data_end LABEL BYTE
test_data_size EQU test_data_end - test_data

.code

PUBLIC Get_Test_Data
Get_Test_Data PROC
    lea     rax, test_data
    mov     edx, test_data_size
    ret
Get_Test_Data ENDP

END
