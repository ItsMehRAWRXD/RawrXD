; ==============================================================================
; SwarmV29_Kernel_Template.asm
; PHASE-29f: Kernel Stub Template (Copy-Paste for New Components)
; Target: Standardized kernel entry point with ABI compliance and error handling
; ------------------------------------------------------------------------------
; Usage:
;   1. Copy this file to a new name (e.g., SwarmV29_NewKernel.asm)
;   2. Replace "Kernel_Name" with your actual function name
#   3. Implement your logic in the "Your Logic Here" section
;   4. Assemble with: ml64 /c /Cx /W3 /nologo /Zi /Fo build\YourKernel.obj src\YourKernel.asm
;
; ABI: Windows x64 (RCX, RDX, R8, R9)
; Dependencies: SwarmV29_Macros.inc
; ==============================================================================

INCLUDE SwarmV29_Macros.inc

; ==============================================================================
; Data Section (Add your static data here)
; ==============================================================================
.data
    ALIGN 64
    
    ; Example: Static lookup tables, constants, etc.
    ; Kernel_Constant DWORD 12345678h

; ==============================================================================
; Code Section
; ==============================================================================
.code
ALIGN 16

; ==============================================================================
; Kernel_Name
; Brief description of what this kernel does
; Input:
;   RCX = First parameter
;   RDX = Second parameter
;   R8  = Third parameter
;   R9  = Fourth parameter
; Output:
;   RAX = 0 on success, error code on failure
; ==============================================================================
Kernel_Name PROC
    SWARM_PROC_START Kernel_Name, <rbx, rdi, rsi>
    
    ; 1. Alignment Check (Required for AVX-512)
    SWARM_CHECK_ALIGN rcx, .Error_Misaligned_Source
    SWARM_CHECK_ALIGN rdx, .Error_Misaligned_Dest
    
    ; 2. NULL Pointer Check
    SWARM_CHECK_NULL rcx, .Error_Null_Pointer
    SWARM_CHECK_NULL rdx, .Error_Null_Pointer
    
    ; 3. Parameter Validation
    test r8, r8
    jz .Error_Invalid_Count
    
    ; 4. Save Parameters
    mov rsi, rcx        ; Source pointer
    mov rdi, rdx        ; Destination pointer
    mov rbx, r8         ; Count/Size
    
    ; ========================================================================
    ; YOUR LOGIC HERE
    ; ========================================================================
    
    ; Example: Simple memory copy loop
    ; .Copy_Loop:
    ;     vmovdqa64 zmm0, [rsi]
    ;     vmovdqa64 [rdi], zmm0
    ;     add rsi, 64
    ;     add rdi, 64
    ;     dec rbx
    ;     jnz .Copy_Loop
    
    ; ========================================================================
    ; END YOUR LOGIC
    ; ========================================================================
    
    ; 5. Success Return
    xor rax, rax
    jmp .Epilogue
    
; ==============================================================================
; Error Handlers
; ==============================================================================
.Error_Misaligned_Source:
    SWARM_SIGNAL_ERROR ERR_MISALIGNED
    
.Error_Misaligned_Dest:
    SWARM_SIGNAL_ERROR ERR_MISALIGNED
    
.Error_Null_Pointer:
    SWARM_SIGNAL_ERROR ERR_NULL_POINTER
    
.Error_Invalid_Count:
    SWARM_SIGNAL_ERROR ERR_INVALID_STATE
    
.Epilogue:
    SWARM_PROC_END
Kernel_Name ENDP

; ==============================================================================
; Kernel_Name_Single
; Single-block variant for inline operations
; Input: ZMM0 = Input data
; Output: ZMM0 = Output data
; ==============================================================================
ALIGN 16
Kernel_Name_Single PROC
    ; Example: Single ZMM operation
    ; vpxord zmm0, zmm0, zmm0
    
    ret
Kernel_Name_Single ENDP

; ==============================================================================
; Kernel_Name_Validate
; Validates input parameters without executing
; Input: Same as Kernel_Name
; Output: RAX = 0 if valid, error code if invalid
; ==============================================================================
ALIGN 16
Kernel_Name_Validate PROC
    SWARM_PROC_START Kernel_Name_Validate, <>
    
    ; Alignment checks
    SWARM_CHECK_ALIGN rcx, .Validation_Failed
    SWARM_CHECK_ALIGN rdx, .Validation_Failed
    
    ; NULL checks
    SWARM_CHECK_NULL rcx, .Validation_Failed
    SWARM_CHECK_NULL rdx, .Validation_Failed
    
    ; Count check
    test r8, r8
    jz .Validation_Failed
    
    ; All valid
    xor rax, rax
    jmp .Epilogue
    
.Validation_Failed:
    mov rax, ERR_INVALID_STATE
    
.Epilogue:
    SWARM_PROC_END
Kernel_Name_Validate ENDP

END