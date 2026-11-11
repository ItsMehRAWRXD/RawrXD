; =============================================================================
; SwarmV29_Test_Macros.asm - Test macro expansion
; =============================================================================

INCLUDE SwarmV29_Macros.inc

.data
ALIGN 16
TestData QWORD 0

.code

PUBLIC SwarmV29_Test_Function

SwarmV29_Test_Function PROC FRAME
    SWARMV29_ABI_FRAME
    
    ; Simple test
    mov rax, 123
    mov QWORD PTR [TestData], rax
    
    SWARMV29_ABI_EPILOG
SwarmV29_Test_Function ENDP

END