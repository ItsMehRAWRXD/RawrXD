include Sovereign_Common.inc
extern g_ApiTable : SOVEREIGN_API_TABLE

.CODE
PUBLIC Sovereign_Action_Dispatcher
Sovereign_Action_Dispatcher PROC
    ; RAX = Pointer to pGov segment
    
    mov rbx, rax
    
    ; Check status/command - we might only want to dispatch if something was generated
    ; For now, we assume if we're here, we want to write the current token
    
    ; Get StdOut
    mov rcx, -11            ; STD_OUTPUT_HANDLE
    call [g_ApiTable.pGetStdHandle]
    test rax, rax
    jz @nothing_to_do
    mov rdi, rax            ; Save hStdOut
    
    ; Write current_token (converted to char if possible, or just raw)
    ; In a real LLM, you'd decode the token first. 
    ; For this kernel, if token < 256, we treat it as ASCII for simplicity in this tick.
    
    mov eax, [rbx].GOV_STATE.current_token
    test eax, eax
    jz @nothing_to_do
    
    mov rcx, rdi            ; hFile
    lea rdx, [rbx].GOV_STATE.current_token ; lpBuffer
    mov r8, 1               ; nNumberOfBytesToWrite (assume 1 byte for now)
    lea r9, [rbx].GOV_STATE.bytes_written ; lpNumberOfBytesWritten
    push 0                  ; lpOverlapped
    call [g_ApiTable.pWriteFile]
    add rsp, 8
    
@nothing_to_do:
    ret
Sovereign_Action_Dispatcher ENDP
END
