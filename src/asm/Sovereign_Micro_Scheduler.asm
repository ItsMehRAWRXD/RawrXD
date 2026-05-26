; =========================================================================================
; FILE: Sovereign_Micro_Scheduler.asm
; SUBSYSTEM: UMS MICRO SCHEDULER (User-Mode Scheduling)
; Pure x64 MASM / No Dependencies / Jitter-Free Priority Lock
; Purpose: Core execution kernel for DAG blocks. Utilizes lock-free spinning and executes
;          JIT logic bound to the Sovereign ABI (R12-R15, XMM12-XMM15 limits).
; =========================================================================================

.CODE

; -----------------------------------------------------------------------------------------
; VOID UMS_Core_Loop(void* pDAGBase, void* pAperture, void* pScratch, void* pTelemetry)
; RCX = pDAGBase   (Mapped to R12 - VM_CONTEXT_PTR)
; RDX = pAperture  (Mapped to R13 - DAG_MATRIX_BASE)
; R8  = pScratch   (Mapped to R14 - SCRATCH_PAD_PTR)
; R9  = pTelemetry (Mapped to R15 - WELFORD_GOV_STATE)
; -----------------------------------------------------------------------------------------
PUBLIC UMS_Core_Loop
UMS_Core_Loop PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    
    ; Lock Sovereign Pinned ABI Registers into hardware state
    push r12
    .pushreg r12
    push r13
    .pushreg r13
    push r14
    .pushreg r14
    push r15
    .pushreg r15
    
    sub rsp, 20h
    .allocstack 20h
    .endprolog

    ; Map the arguments to the Execution Graph Register ABI
    mov r12, rcx  
    mov r13, rdx  
    mov r14, r8   
    mov r15, r9   

@@SpinCycle:
    ; Status check of DAG Node at [r12]
    ; Convention: 0 = IDLE, 1 = READY, 2 = SHUTDOWN, 3 = COMPLETE
    mov eax, dword ptr [r12]
    cmp eax, 2
    je @@Terminate

    cmp eax, 1
    jne @@ThermalRelief

    ; Status == 1 (Ready for Execution)
    ; Extract kernel JIT / dispatch pointer from [r12 + 8]
    mov rax, qword ptr [r12 + 8]
    test rax, rax
    jz @@ThermalRelief

    ; Dispatch to JIT workload. Pinned registers strictly preserved. 
    ; Shadow space is allocated; standard x64 `call` applies.
    call rax

    ; Set Node to COMPLETE (Status = 3)
    ; Issue sfence to ensure memory writes from JIT hit globally before status flip
    sfence
    mov eax, 3
    mov dword ptr [r12], eax

@@ThermalRelief:
    ; Thermal-optimized pause to grant hyper-threads pipeline resources
    pause
    jmp @@SpinCycle

@@Terminate:
    add rsp, 20h
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret
UMS_Core_Loop ENDP

END