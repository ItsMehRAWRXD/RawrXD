; Test with macros
INCLUDE SwarmV29_Macros.inc

.data
ALIGN 16
TestData QWORD 0

.code

PUBLIC TestFunctionWithMacros

TestFunctionWithMacros PROC FRAME
    SWARMV29_ABI_FRAME
    
    mov rax, 123
    mov QWORD PTR [TestData], rax
    
    SWARMV29_ABI_EPILOG
TestFunctionWithMacros ENDP

END