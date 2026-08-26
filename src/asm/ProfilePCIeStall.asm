; ============================================================================
; ProfilePCIeStall.asm - PCIe Micro-Stall Profiler for R9700
; Measures exact CPU clock cycles for AVX-512 non-temporal store across PCIe
; ============================================================================

.code

; extern "C" uint64_t ProfilePCIeStall(void* mapped_vram, void* sys_ram);
; RCX = mapped_vram (Destination over PCIe)
; RDX = sys_ram     (Source in system RAM)
ProfilePCIeStall PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    .endprolog

    mov rsi, rcx        ; RSI = dest (mapped VRAM)
    mov rbx, rdx        ; RBX = src (system RAM)

    ; Serialize execution
    mfence
    lfence

    ; Get start time
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov r8, rax         ; R8 = start ticks

    ; Execute 64-byte AVX-512 transfer
    vmovdqa64 zmm0, zmmword ptr [rbx]
    vmovntdq zmmword ptr [rsi], zmm0

    ; Force flush across PCIe
    mfence

    ; Get end time
    rdtscp
    shl rdx, 32
    or rax, rdx

    ; Calculate delta
    sub rax, r8         ; RAX = delta ticks

    pop rsi
    pop rbx
    ret
ProfilePCIeStall ENDP

; ============================================================================
; Batch profile: run N iterations and return average + max
; ============================================================================

; extern "C" void ProfilePCIeStallBatch(void* mapped_vram, void* sys_ram,
;                                       uint32_t iterations,
;                                       uint64_t* out_avg_ns,
;                                       uint64_t* out_max_ns);
; RCX = mapped_vram
; RDX = sys_ram
; R8  = iterations
; R9  = out_avg_ns
; [RSP+40] = out_max_ns
ProfilePCIeStallBatch PROC FRAME
    push rbx
    .pushreg rbx
    push rdi
    .pushreg rdi
    push rsi
    .pushreg rsi
    push r12
    .pushreg r12
    push r13
    .pushreg r13
    .endprolog

    mov rsi, rcx            ; RSI = mapped_vram
    mov rdi, rdx            ; RDI = sys_ram
    mov r12, r8             ; R12 = iterations
    mov r13, r9             ; R13 = out_avg_ns
    mov rbx, qword ptr [rsp+48] ; RBX = out_max_ns (stack offset after pushes)

    xor rax, rax
    mov qword ptr [r13], rax    ; *out_avg_ns = 0
    mov qword ptr [rbx], rax    ; *out_max_ns = 0

    test r12, r12
    jz done_batch

    xor r8, r8              ; R8 = sum
    xor r9, r9              ; R9 = max

batch_loop:
    ; Call single measurement
    mov rcx, rsi
    mov rdx, rdi
    call ProfilePCIeStall

    add r8, rax
    cmp rax, r9
    cmova r9, rax           ; Update max if greater

    dec r12
    jnz batch_loop

    ; Calculate average
    mov rax, r8
    mov rcx, r12            ; iterations (original count)
    ; Need to preserve original iteration count - use stack
    xor rdx, rdx
    div rcx
    mov qword ptr [r13], rax

    ; Store max
    mov qword ptr [rbx], r9

done_batch:
    pop r13
    pop r12
    pop rsi
    pop rdi
    pop rbx
    ret
ProfilePCIeStallBatch ENDP

END
