; Sovereign_DAG_VM_Fixed.asm - Logic Graph Execution Engine
; Fixed for Win64 ABI register volatility and stack safety
; -----------------------------------------------------------------------------

.code

PUBLIC XR_DAG_Execute_Fixed
XR_DAG_Execute_Fixed PROC
    push rbp
    mov rbp, rsp
    sub rsp, 48                ; Shadow space + local safety
    
    ; Protect Non-Volatile Registers (Worker State)
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15

    ; RCX = pGraph
    ; RDX = NodeCount
    mov r12, rcx               ; r12 = Current Node
    mov r13, rdx               ; r13 = Loop Counter
    
L_DagLoop:
    test r13, r13
    jz L_DagDone

    ; Fetch Node Opcode
    mov eax, dword ptr [r12]
    
    ; [FIX] Always preserve R12/R13 before any external call or dispatch
    ; Use R14/R15 for transient work
    mov r14, [r12 + 8]         ; Node Data Ptr
    
    ; Dispatch logic...
    ; (Simplified for drop-in validation)
    
    add r12, 16                ; sizeof(DAG_NODE)
    dec r13
    jmp L_DagLoop

L_DagDone:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    mov rsp, rbp
    pop rbp
    ret
XR_DAG_Execute_Fixed ENDP

end