; Test with macros but no FRAME
INCLUDE SwarmV29_Macros.inc

.data
ALIGN 16
TestData QWORD 0

.code

PUBLIC TestFunctionNoFrame

TestFunctionNoFrame PROC
    SWARMV29_ABI_FRAME
    
    mov rax, 123
    mov QWORD PTR [TestData], rax
    
    SWARMV29_ABI_EPILOG
TestFunctionNoFrame ENDP

END