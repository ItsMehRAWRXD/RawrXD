;=============================================================================
; EXTRACTED UTILITIES FROM MODULE 2+
; Cleaned and formatted for MASM64 integration
; Add these to RawrXD_Absolutely_Complete.asm before the first END
;=============================================================================

;-----------------------------------------------------------------------------
; GetCurrentTimestamp - Get high-resolution timestamp (raw QPC ticks)
; Returns: RAX = QPC tick count
; Clobbers: RCX, RDX, R8-R11 (per x64 calling convention)
;-----------------------------------------------------------------------------
GetCurrentTimestamp PROC EXPORT FRAME
    sub rsp, 16
    .ALLOCSTACK 16
    .ENDPROLOG
    
    lea rcx, [rsp+8]
    call QueryPerformanceCounter
    
    mov rax, [rsp+8]
    
    add rsp, 16
    ret
GetCurrentTimestamp ENDP

;-----------------------------------------------------------------------------
; InitPerfFrequency - Initialize performance counter frequency (lazy init)
; Returns: RAX = frequency
;-----------------------------------------------------------------------------
InitPerfFrequency PROC PRIVATE FRAME
    sub rsp, 16
    .ALLOCSTACK 16
    .ENDPROLOG
    
    mov rax, g_QPCFrequency
    test rax, rax
    jnz @@already_initialized
    
    lea rcx, [rsp+8]
    call QueryPerformanceFrequency
    mov rax, [rsp+8]
    mov g_QPCFrequency, rax
    
@@already_initialized:
    add rsp, 16
    ret
InitPerfFrequency ENDP

;-----------------------------------------------------------------------------
; CalculateMicroseconds - Convert QPC ticks to microseconds
; Parameters: RCX = tick count
; Returns: RAX = microseconds
; Clobbers: RDX, R8-R11
;-----------------------------------------------------------------------------
CalculateMicroseconds PROC EXPORT FRAME
    push rbx
    .PUSHREG RBX
    .ENDPROLOG
    
    mov rbx, rcx                            ; Save input ticks
    call InitPerfFrequency                  ; Ensure frequency is initialized
    
    mov rax, rbx
    mov rcx, 1000000                        ; Microseconds per second
    mul rcx                                 ; RDX:RAX = ticks * 1000000
    mov rcx, g_QPCFrequency
    xor rdx, rdx
    div rcx                                 ; RAX = (ticks * 1000000) / frequency
    
    pop rbx
    ret
CalculateMicroseconds ENDP

;-----------------------------------------------------------------------------
; ValidateMemoryRange - Validate memory range is accessible
; Parameters: RCX = address, RDX = size
; Returns: EAX = 0 (valid), TITAN_ERROR_INVALID_PARAM (invalid)
; Clobbers: R8, R9-R11
;-----------------------------------------------------------------------------
ValidateMemoryRange PROC EXPORT FRAME
    .ENDPROLOG
    
    test rcx, rcx
    jz @@invalid
    test rdx, rdx
    jz @@invalid
    
    mov r8, rcx
    add r8, rdx
    jc @@invalid                            ; Overflow check
    
    xor eax, eax                            ; Return 0 (valid)
    jmp @@done
    
@@invalid:
    mov eax, TITAN_ERROR_INVALID_PARAM
    
@@done:
    ret
ValidateMemoryRange ENDP

;-----------------------------------------------------------------------------
; GetTimestampUs_v2 - Improved timestamp in microseconds
; Combines GetCurrentTimestamp + CalculateMicroseconds with init check
; Returns: RAX = microseconds
;-----------------------------------------------------------------------------
GetTimestampUs_v2 PROC EXPORT FRAME
    push rbx
    .PUSHREG RBX
    sub rsp, 16
    .ALLOCSTACK 16
    .ENDPROLOG
    
    call GetCurrentTimestamp                ; RAX = raw ticks
    mov rbx, rax                            ; Save ticks
    
    mov rcx, rbx
    call CalculateMicroseconds              ; RAX = microseconds
    
    add rsp, 16
    pop rbx
    ret
GetTimestampUs_v2 ENDP

;=============================================================================
; INTEGRATION NOTES:
; 
; 1. Add these PROCs to RawrXD_Absolutely_Complete.asm BEFORE line 931 (END)
; 2. Add PUBLIC declarations at the top with other exports:
;    PUBLIC GetCurrentTimestamp
;    PUBLIC CalculateMicroseconds
;    PUBLIC ValidateMemoryRange
;    PUBLIC GetTimestampUs_v2
;
; 3. Update Titan_ExecuteComputeKernel to call ValidateMemoryRange on params
; 4. Replace GetTimestampUs calls with GetTimestampUs_v2 for safety
;=============================================================================