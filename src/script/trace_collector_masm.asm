; RawrXD-Script Trace Collector MASM Integration
; Provides C-callable wrappers for TraceCollector API

.CODE

; TraceCollector_RecordOpcode - Record an opcode execution event
; Entry: rcx = opcode (uint16_t), rdx = pc (uint64_t)
; Exit:  none
TraceCollector_RecordOpcode PROC FRAME
    push rbp
    .pushreg rbp
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    push r12
    .pushreg r12
    push r13
    .pushreg r13
    push r14
    .pushreg r14
    push r15
    .pushreg r15
    sub rsp, 40
    .allocstack 40
    .endprolog
    
    ; Save parameters
    mov r14, rcx            ; r14 = opcode
    mov r15, rdx            ; r15 = pc
    
    ; Call C function: TraceCollector_RecordOpcode(opcode, pc)
    ; RCX = opcode, RDX = pc
    mov rcx, r14
    mov rdx, r15
    
    ; We need to call the C++ function via extern "C" wrapper
    ; For now, store in our own trace buffer that C++ can read
    
    ; Get trace index
    mov rax, OFFSET g_trace_index_asm
    mov rbx, [rax]
    
    ; Check bounds (TRACE_BUFFER_SIZE = 4096)
    cmp rbx, 4096
    jae @record_done
    
    ; Store event: [type:16][opcode:16][pc:32] packed into 64 bits
    ; Type 1 = OPCODE
    shl r14, 16
    or r14, 1               ; type = 1 (OPCODE)
    shl r15, 32
    or r14, r15             ; r14 = [pc:32][opcode:16][type:16]
    
    ; Store in buffer
    mov rax, OFFSET g_trace_buffer_asm
    mov [rax + rbx*8], r14
    
    ; Increment index
    inc rbx
    mov rax, OFFSET g_trace_index_asm
    mov [rax], rbx
    
@record_done:
    add rsp, 40
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret
TraceCollector_RecordOpcode ENDP

; TraceCollector_RecordRegister - Record a register access event
; Entry: rcx = reg_index (uint8_t), rdx = value (uint64_t)
; Exit:  none
TraceCollector_RecordRegister PROC FRAME
    push rbp
    .pushreg rbp
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    push r12
    .pushreg r12
    push r13
    .pushreg r13
    push r14
    .pushreg r14
    push r15
    .pushreg r15
    sub rsp, 40
    .allocstack 40
    .endprolog
    
    mov r14, rcx            ; r14 = reg_index
    mov r15, rdx            ; r15 = value
    
    ; Get trace index
    mov rax, OFFSET g_trace_index_asm
    mov rbx, [rax]
    
    ; Check bounds
    cmp rbx, 4096
    jae @record_reg_done
    
    ; Store event: [type:16][reg:16][value_hi:32] in first qword
    ; Type 2 = REGISTER
    shl r14, 16
    or r14, 2               ; type = 2 (REGISTER)
    
    ; Store first part
    mov rax, OFFSET g_trace_buffer_asm
    mov [rax + rbx*8], r14
    inc rbx
    
    ; Check bounds again
    cmp rbx, 4096
    jae @record_reg_done
    
    ; Store value in second slot
    mov [rax + rbx*8], r15
    inc rbx
    
    ; Update index
    mov rax, OFFSET g_trace_index_asm
    mov [rax], rbx
    
@record_reg_done:
    add rsp, 40
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret
TraceCollector_RecordRegister ENDP

; TraceCollector_GetFingerprint - Generate fingerprint from trace buffer
; Entry: rcx = result pointer (uint64_t[2] for hash_a, hash_b)
; Exit:  none
TraceCollector_GetFingerprint PROC FRAME
    push rbp
    .pushreg rbp
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    push r12
    .pushreg r12
    push r13
    .pushreg r13
    push r14
    .pushreg r14
    push r15
    .pushreg r15
    sub rsp, 40
    .allocstack 40
    .endprolog
    
    mov rdi, rcx            ; rdi = result pointer
    
    ; Initialize FNV-1a hash (two independent hashes for 128-bit)
    ; hash_a = FNV_OFFSET_BASIS = 0xcbf29ce484222325
    mov r12, 0CBF29CE484222325h
    ; hash_b = FNV_OFFSET_BASIS ^ 0FFFFFFFFFFFFFFFFh (different seed)
    mov r13, 3403613B7BDDCDDAh  ; ~FNV_OFFSET_BASIS
    
    ; FNV_PRIME = 0x100000001b3
    mov r14, 100000001B3h
    
    ; Get trace count
    mov rax, OFFSET g_trace_index_asm
    mov rcx, [rax]          ; rcx = count
    test rcx, rcx
    jz @fingerprint_done    ; Empty trace
    
    ; Process each event
    xor rbx, rbx            ; rbx = index
    mov rsi, OFFSET g_trace_buffer_asm
    
@hash_loop:
    cmp rbx, rcx
    jae @fingerprint_done
    
    ; Load event
    mov rax, [rsi + rbx*8]
    inc rbx
    
    ; Update hash_a
    xor r12, rax
    mov rax, r12
    mul r14                 ; rax = hash_a * FNV_PRIME
    mov r12, rax
    
    ; Update hash_b (with bit rotation)
    ror rax, 17             ; Rotate for hash_b
    xor r13, rax
    mov rax, r13
    mul r14
    mov r13, rax
    
    jmp @hash_loop
    
@fingerprint_done:
    ; Store result
    mov [rdi], r12          ; hash_a
    mov [rdi+8], r13        ; hash_b
    
    add rsp, 40
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret
TraceCollector_GetFingerprint ENDP

; TraceCollector_Clear - Clear the trace buffer
; Entry: none
; Exit:  none
TraceCollector_Clear PROC FRAME
    push rbp
    .pushreg rbp
    sub rsp, 8
    .allocstack 8
    .endprolog
    
    mov rax, OFFSET g_trace_index_asm
    mov QWORD PTR [rax], 0
    
    add rsp, 8
    pop rbp
    ret
TraceCollector_Clear ENDP

; TraceCollector_GetEventCount - Get number of events in buffer
; Entry: none
; Exit:  rax = event count
TraceCollector_GetEventCount PROC FRAME
    push rbp
    .pushreg rbp
    sub rsp, 8
    .allocstack 8
    .endprolog
    mov rax, OFFSET g_trace_index_asm
    mov rax, [rax]
    add rsp, 8
    pop rbp
    ret
TraceCollector_GetEventCount ENDP

; TraceCollector_GetBufferPtr - Get pointer to trace buffer
; Entry: none
; Exit:  rax = pointer to g_trace_buffer_asm
TraceCollector_GetBufferPtr PROC FRAME
    push rbp
    .pushreg rbp
    sub rsp, 8
    .allocstack 8
    .endprolog
    mov rax, OFFSET g_trace_buffer_asm
    add rsp, 8
    pop rbp
    ret
TraceCollector_GetBufferPtr ENDP

.DATA

ALIGN 16

; Trace buffer for MASM-collected events
; 4096 events * 8 bytes = 32KB
PUBLIC g_trace_buffer_asm
g_trace_buffer_asm QWORD 4096 DUP(0)

; Current index into trace buffer
PUBLIC g_trace_index_asm
g_trace_index_asm QWORD 0

END
