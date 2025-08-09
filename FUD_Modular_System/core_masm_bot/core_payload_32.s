# ===============================================================================
# CORE PAYLOAD - 32-bit Assembly for MinGW
# Simplified version for cross-platform compilation
# ===============================================================================

.intel_syntax noprefix
.arch i386
.text

.global _start

# ===============================================================================
# DATA SECTION
# ===============================================================================
.section .data

default_cmd:
    .asciz "calc.exe"

# ===============================================================================
# MAIN ENTRY POINT
# ===============================================================================
.section .text

_start:
    # Simple payload execution
    call execute_payload
    
    # Exit
    push 0
    call _ExitProcess@4

# ===============================================================================
# PAYLOAD EXECUTION
# ===============================================================================
execute_payload:
    # Execute calc.exe using system()
    push offset default_cmd
    call _system
    add esp, 4
    ret

# ===============================================================================
# EXTERNAL FUNCTION DECLARATIONS
# ===============================================================================
.extern _ExitProcess@4
.extern _system