PUBLIC RUNTIME_DISPATCH
.DATA
ALIGN 64
; Scheduler ABI: Dispatch Table for DAG Nodes
DISPATCH_TABLE DQ KERNEL_Q4, KERNEL_Q5, KERNEL_SIMD
.CODE
RUNTIME_DISPATCH PROC FRAME
    push rbx                    ; ABI: Save non-volatile
    push rsi                    ; ABI: Save non-volatile
    push rdi                    ; ABI: Save non-volatile
    sub rsp, 28h                ; ABI: Shadow space
    mov rax, [rcx + r8*8]       ; Dispatch: Load node addr (RCX=Table, R8=Index)
    mov rsi, [rdx]              ; Args: Load Base
    mov rdi, [rdx+8]            ; Args: Load Count
    mov r8,  [rdx+16]           ; Args: Load Stride
    call rax                    ; Execute: Jump to DAG Node
    add rsp, 28h                ; ABI: Restore stack
    pop rdi                     ; ABI: Restore non-volatile
    pop rsi                     ; ABI: Restore non-volatile
    pop rbx                     ; ABI: Restore non-volatile
    ret                         ; Scheduler Return
RUNTIME_DISPATCH ENDP
KERNEL_Q4 PROC FRAME
    lea rbx, [rsi + r8*18]      ; Set Bound
    cmp rsi, rbx                ; Loop Head
    jae .done
    vmovups xmm0, [rsi + 2]     ; Process
    add rsi, 18                 ; Stride
    jmp $-10                    ; Loop
.done: ret
KERNEL_Q4 ENDP
KERNEL_Q5 PROC FRAME
    lea rbx, [rsi + r8*176]     ; Set Bound
    cmp rsi, rbx                ; Loop Head
    jae .done
    vmovups xmm0, [rsi]         ; Process
    add rsi, 176                ; Stride
    jmp $-10                    ; Loop
.done: ret
KERNEL_Q5 ENDP
KERNEL_SIMD PROC FRAME
    lea rbx, [rsi + r8*4]       ; Set Bound
    cmp rsi, rbx                ; Loop Head
    jae .done
    vmovss xmm0, [rsi]          ; Process
    add rsi, 4                  ; Stride
    jmp $-10                    ; Loop
.done: ret
KERNEL_SIMD ENDP
END
