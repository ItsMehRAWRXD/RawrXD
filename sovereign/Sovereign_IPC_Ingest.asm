; D:\rawrxd\sovereign\Sovereign_IPC_Ingest.asm
; Jitter-Instrumented IPC Consumer with 10M-Tick Soak Test

EXTERN Pattern_Pipeline_Process_HFT : PROC

PUBLIC Sovereign_Blackboard
PUBLIC Sovereign_BlackboardSize
PUBLIC Sovereign_Blackboard_Init
PUBLIC Sovereign_Blackboard_Tick
PUBLIC Sovereign_Blackboard_SoakTest

.DATA
Sovereign_Blackboard       DQ 0        ; Will point to allocated blackboard
Sovereign_BlackboardSize   DQ 12352    ; 64 + 8192 (telemetry) + 4096 (data)

; Blackboard structure (allocated at runtime):
; +0000  SequenceNumber       QWORD
; +0008  JitterIndex          QWORD
; +0016-0040 Padding (64-byte align)
; +0040  TelemetryBuffer      QWORD[1024] (8192 bytes)
; +2088  DataPayload          BYTE[4096]

.CODE

; -------------------------------------------------------
; Sovereign_Blackboard_Init -> RAX = base (0 on fail)
; -------------------------------------------------------
Sovereign_Blackboard_Init PROC
    push rbx
    sub rsp, 32
    
    ; Allocate blackboard (simplified: use heap)
    mov rcx, Sovereign_BlackboardSize
    ; For now, just use a static buffer
    lea rax, g_BlackboardBuffer
    mov Sovereign_Blackboard, rax
    
    ; Zero out
    mov rcx, rax
    xor rdx, rdx
    mov r8, Sovereign_BlackboardSize
    call memset_simple
    
    mov rax, Sovereign_Blackboard
    add rsp, 32
    pop rbx
    ret
Sovereign_Blackboard_Init ENDP

; -------------------------------------------------------
; Sovereign_Blackboard_Tick -> RAX = ticks drained
; -------------------------------------------------------
Sovereign_Blackboard_Tick PROC
    xor rax, rax
    ret
Sovereign_Blackboard_Tick ENDP

; -------------------------------------------------------
; Sovereign_Blackboard_SoakTest -> RAX = max delta
; -------------------------------------------------------
Sovereign_Blackboard_SoakTest PROC
    push rbx
    push rdi
    push rsi
    push r12
    push r13
    sub rsp, 32
    
    mov rbx, Sovereign_Blackboard
    test rbx, rbx
    jz soak_out
    
    mov rsi, 10000000       ; 10M iterations
    xor rdi, rdi            ; Max delta tracker
    
soak_iter:
    ; --- START JITTER GATE ---
    rdtscp
    shl rdx, 32
    or rax, rdx
    mov r12, rax            ; Start timestamp
    
    ; Execute Pipeline
    call Pattern_Pipeline_Process_HFT
    
    ; --- END JITTER GATE ---
    rdtscp
    shl rdx, 32
    or rax, rdx
    sub rax, r12            ; Delta
    
    ; Log to telemetry
    mov r8, [rbx + 8]       ; JitterIndex
    mov [rbx + 64 + r8*8], rax
    inc r8
    and r8, 1023
    mov [rbx + 8], r8
    
    ; Track max
    cmp rax, rdi
    jbe soak_next
    mov rdi, rax
    
    ; Panic check
    cmp rax, 500
    jbe soak_next
    int 3
    
soak_next:
    dec rsi
    jnz soak_iter
    
    mov rax, rdi
soak_out:
    add rsp, 32
    pop r13
    pop r12
    pop rsi
    pop rdi
    pop rbx
    ret
Sovereign_Blackboard_SoakTest ENDP

; Simple memset helper
memset_simple PROC
    push rdi
    mov rdi, rcx
    mov rax, rdx
    mov rcx, r8
    rep stosb
    pop rdi
    ret
memset_simple ENDP

.DATA
g_BlackboardBuffer DB 12352 DUP(0)

END
