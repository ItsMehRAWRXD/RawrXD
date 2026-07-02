; =============================================================================
; genesis_masm64_minimal.asm
; Minimal working version - demonstrates the concept
; =============================================================================

; External functions
        EXTRN ExitProcess:PROC

        .code

main    PROC
        ; Simple exit with code 0 (success)
        xor     ecx, ecx        ; Exit code 0
        call    ExitProcess
main    ENDP

        END
