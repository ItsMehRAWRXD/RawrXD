; ==============================================================================
; Sovereign_Register_Map.inc - Register Volatility Contract
; ==============================================================================
; Formalizes ownership policies for Win64 nonvolatile registers.
; Volatile: RAX, RCX, RDX, R8, R9, R10, R11
; Nonvolatile: RBX, RBP, RDI, RSI, R12, R13, R14, R15

; Macro to enter a standard scope preserving common nonvolatile registers
ENTER_VOLATILE_SCOPE MACRO
    push rbx
    push rdi
    push rsi
ENDM

; Macro to exit a standard scope
EXIT_VOLATILE_SCOPE MACRO
    pop rsi
    pop rdi
    pop rbx
ENDM

; Macro to enter a deep compute scope preserving all extended registers
ENTER_COMPUTE_SCOPE MACRO
    push rbx
    push rbp
    push rdi
    push rsi
    push r12
    push r13
    push r14
    push r15
ENDM

; Macro to exit a deep compute scope
EXIT_COMPUTE_SCOPE MACRO
    pop r15
    pop r14
    pop r13
    pop r12
    pop rsi
    pop rdi
    pop rbp
    pop rbx
ENDM
