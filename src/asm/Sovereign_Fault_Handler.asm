.CODE
EXTERN AddVectoredExceptionHandler : PROC
EXTERN GetCurrentProcess : PROC
EXTERN WriteFile : PROC
EXTERN g_BlackBoxBuffer : BYTE
EXTERN XR_FaultLog_Flush : PROC

; The Fault Handler Callback
; RCX = PEXCEPTION_POINTERS
PUBLIC XR_Fault_Handler_Entry
XR_Fault_Handler_Entry PROC
    ; 1. Preserve registers
    push rax
    push rbx
    push r8
    push r9
    push rsi
    push rdi
    
    ; 2. Extract Context (ExceptionRecord at [RCX], ContextRecord at [RCX + 8])
    mov r8, [rcx]           ; r8 = ExceptionRecord
    mov r9, [rcx + 8]       ; r9 = ContextRecord
    
    ; 3. Base of the Black Box NVMe Sector buffer
    lea rdi, [g_BlackBoxBuffer]
    
    ; 4. Log ExceptionCode (Offset 0x0 in ExceptionRecord)
    mov eax, dword ptr [r8]
    mov dword ptr [rdi], eax
    
    ; 5. Log Faulting Memory Address / CR2 (Offset 0x28 ExceptionInformation[1])
    mov rax, [r8 + 28h]
    mov qword ptr [rdi + 8], rax
    
    ; 6. Log RIP of fault (Offset 0x0F8 in ContextRecord)
    mov rax, [r9 + 0F8h]   
    mov qword ptr [rdi + 10h], rax
    
    ; 7. Log RSP (Offset 0x98 in ContextRecord)
    mov rax, [r9 + 98h]
    mov qword ptr [rdi + 18h], rax
    
    ; 8. Log RBP (Offset 0xA0 in ContextRecord)
    mov rax, [r9 + 0A0h]
    mov qword ptr [rdi + 20h], rax
    
    ; Setup flush call arguments and invoke
    ; The user requested rcx, rdx, r8, r9 to be populated for the flush maybe for debugging:
    mov rcx, [r8+0]                 ; ExceptionCode
    mov rdx, [r8+28h]               ; ExceptionInformation[1] (faulting address)
    push r8
    mov r8, [r9+0F8h]               ; ContextRecord->Rip
    mov r9, [r9+98h]                ; ContextRecord->Rsp
    call XR_FaultLog_Flush
    pop r8
    
    ; 9. Signal EXCEPTION_CONTINUE_SEARCH (0)
    pop rdi
    pop rsi
    pop r9
    pop r8
    pop rbx
    pop rax
    mov rax, 0
    ret
XR_Fault_Handler_Entry ENDP

PUBLIC XR_Install_Fault_Hooks
XR_Install_Fault_Hooks PROC
    sub rsp, 40
    mov rcx, 1 ; First handler
    lea rdx, [XR_Fault_Handler_Entry]
    call AddVectoredExceptionHandler
    add rsp, 40
    ret
XR_Install_Fault_Hooks ENDP
END
