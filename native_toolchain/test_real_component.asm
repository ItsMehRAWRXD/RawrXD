; ============================================================================
; Real Component Test - Native Toolchain
; Tests actual functionality: function calls, data sections, exports
; This is NOT a hello world - it's a real component
; ============================================================================

.code

; Export table (for DLL creation)
; public MyComponent_Init
; public MyComponent_Process
; public MyComponent_Shutdown

; ============================================================================
; MyComponent_Init - Initialize the component
; Returns: 0 on success, non-zero on failure
; ============================================================================
MyComponent_Init:
    push rbp
    mov rbp, rsp
    sub rsp, 32
    
    ; Initialize component state
    mov qword ptr [ComponentState], 1    ; Set initialized flag
    mov qword ptr [ProcessCount], 0     ; Reset process counter
    
    ; Return success
    xor rax, rax
    add rsp, 32
    pop rbp
    ret

; ============================================================================
; MyComponent_Process - Process data
; RCX = input data pointer
; RDX = output data pointer
; R8 = data size
; Returns: number of bytes processed
; ============================================================================
MyComponent_Process:
    push rbp
    mov rbp, rsp
    push rbx
    push rdi
    push rsi
    sub rsp, 32
    
    ; Check if initialized
    mov rax, qword ptr [ComponentState]
    test rax, rax
    jz .not_initialized
    
    ; Copy data (simple memcpy)
    mov rsi, rcx      ; Source
    mov rdi, rdx      ; Destination
    mov rcx, r8       ; Count
    
    ; Process loop
    xor rbx, rbx      ; Bytes processed
.process_loop:
    test rcx, rcx
    jz .done
    
    ; Load byte
    mov al, byte ptr [rsi]
    
    ; Simple processing: invert bits
    not al
    
    ; Store byte
    mov byte ptr [rdi], al
    
    ; Increment counters
    inc rsi
    inc rdi
    inc rbx
    dec rcx
    jmp .process_loop
    
.done:
    ; Update process count
    inc qword ptr [ProcessCount]
    
    ; Return bytes processed
    mov rax, rbx
    jmp .exit
    
.not_initialized:
    mov rax, -1       ; Error: not initialized
    
.exit:
    add rsp, 32
    pop rsi
    pop rdi
    pop rbx
    pop rbp
    ret

; ============================================================================
; MyComponent_Shutdown - Clean up
; ============================================================================
MyComponent_Shutdown:
    push rbp
    mov rbp, rsp
    sub rsp, 32
    
    ; Clear component state
    mov qword ptr [ComponentState], 0
    
    ; Return final process count
    mov rax, qword ptr [ProcessCount]
    
    add rsp, 32
    pop rbp
    ret

; ============================================================================
; MyComponent_GetVersion - Get component version
; Returns: version number in RAX
; ============================================================================
MyComponent_GetVersion:
    mov rax, 0x00010002    ; Version 1.2
    ret

; ============================================================================
; MyComponent_GetStats - Get processing statistics
; RCX = pointer to stats structure
; ============================================================================
MyComponent_GetStats:
    push rbp
    mov rbp, rsp
    
    ; Fill stats structure
    mov rax, qword ptr [ProcessCount]
    mov qword ptr [rcx], rax      ; Stats.processCount
    mov rax, qword ptr [ComponentState]
    mov qword ptr [rcx+8], rax    ; Stats.initialized
    
    pop rbp
    ret

; ============================================================================
; Entry point for standalone executable
; ============================================================================
mainCRTStartup:
    ; Initialize
    call MyComponent_Init
    test rax, rax
    jnz .init_failed
    
    ; Test data
    sub rsp, 256
    mov rcx, rsp
    mov rdx, rsp
    add rdx, 128
    mov r8, 16
    
    ; Fill test data
    mov rdi, rcx
    mov rcx, 16
.fill_loop:
    mov byte ptr [rdi], cl
    inc rdi
    loop .fill_loop
    
    ; Process
    mov rcx, rsp
    mov rdx, rsp
    add rdx, 128
    mov r8, 16
    call MyComponent_Process
    
    ; Cleanup
    add rsp, 256
    call MyComponent_Shutdown
    
    ; Exit with success
    xor rcx, rcx
    mov rax, 60         ; sys_exit (Linux) - placeholder
    ; On Windows, call ExitProcess
    ret
    
.init_failed:
    ; Exit with error
    mov rcx, 1
    ret

.data

; Component state
ComponentState:
    .quad 0

ProcessCount:
    .quad 0

; Version string
VersionString:
    .asciz "MyComponent v1.2 - Native Toolchain Test"

; Stats structure layout (for documentation)
; struct Stats {
;     uint64_t processCount;
;     uint64_t initialized;
;     uint64_t reserved[6];
; }

.end
