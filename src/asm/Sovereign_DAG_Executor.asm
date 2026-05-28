; ==============================================================================
; SOVEREIGN DAG EXECUTOR
; File: Sovereign_DAG_Executor.asm
; Role: Flattened, Static-Order Kernel Dispatch
; ==============================================================================

include Sovereign_Common.inc
include Sovereign_FrameABI.inc

; DAG Node Structure
DAG_NODE STRUCT
    KernelPtr   QWORD ?  ; Function pointer
    InputHash   QWORD ?  ; Registry Hash (Input)
    OutputHash  QWORD ?  ; Registry Hash (Output)
    ParamCount  QWORD ?  ; Payload size
DAG_NODE ENDS

.DATA
    g_DAG_Head  QWORD 0  ; Pointer to first node
    g_DAG_Count QWORD 0  ; Total execution steps

.CODE

EXTERN Sovereign_Registry_Lookup:PROC
EXTERN Sovereign_Shadow_Acquire:PROC
EXTERN Sovereign_Shadow_Update:PROC
EXTERN Sovereign_Ghost_Log:PROC

; RCX = Ptr to Node Array, RDX = Count
PUBLIC Sovereign_DAG_Initialize
Sovereign_DAG_Initialize PROC
    mov [g_DAG_Head], rcx
    mov [g_DAG_Count], rdx
    ret
Sovereign_DAG_Initialize ENDP

; Single-Pass Flattened Executor
PUBLIC Sovereign_DAG_Execute
Sovereign_DAG_Execute PROC
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    ENTER_FRAME
    
    mov rsi, [g_DAG_Head] ; RSI = Cursor
    mov rbx, [g_DAG_Count] ; RBX = Counter
    
    test rbx, rbx
    jz @@Done

@@NodeLoop:
    ; Calculate Node Index for Shadow Map (R14)
    mov r14, rsi
    sub r14, [g_DAG_Head]
    shr r14, 5             ; divide by 32 (size of DAG_NODE)
    
    ; Request Schedule
    mov rcx, r14
    call Sovereign_Shadow_Acquire

    ; 1. Resolve Input/Output Pointers from Registry
    mov rcx, [rsi + DAG_NODE.InputHash]
    call Sovereign_Registry_Lookup
    mov r12, rax           ; R12 = Input Buffer (Preserved in non-volatile)
    
    mov rcx, [rsi + DAG_NODE.OutputHash]
    call Sovereign_Registry_Lookup
    mov r13, rax           ; R13 = Output Buffer (Preserved in non-volatile)

    ; GHOST LOG: BEFORE EXECUTION
    mov rcx, [rsi + DAG_NODE.KernelPtr] ; NodeID = KernelPtr
    mov rdx, 0
    call Sovereign_Ghost_Log

    ; 2. Dispatch Kernel
    ; Kernel Expects: RCX=Input, RDX=Output, R8=Size
    mov rcx, r12
    mov rdx, r13
    mov r8, [rsi + DAG_NODE.ParamCount]
    call [rsi + DAG_NODE.KernelPtr]

    ; Save Kernel Exit Code
    mov r15, rax

    ; GHOST LOG: AFTER EXECUTION
    mov rcx, [rsi + DAG_NODE.KernelPtr]
    mov rdx, r15
    call Sovereign_Ghost_Log

    ; 3. Signal Completion
    mov rcx, r14
    mov rdx, 3 ; SHADOW_STATE_DONE
    call Sovereign_Shadow_Update

    ; Advance to next node
    add rsi, TYPE DAG_NODE
    dec rbx
    jnz @@NodeLoop

@@Done:
    EXIT_FRAME
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
Sovereign_DAG_Execute ENDP

END
