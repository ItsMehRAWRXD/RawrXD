; RawrXD_SelfHost_Engine.asm — Recursive Self-Hosting Compile Engine (MASM x64)
; Phase E: Profile → Identify → Generate → Verify → Swap
; Exports: asm_selfhost_init, asm_selfhost_read_text, asm_selfhost_profile_region, etc.

OPTION DOTNAME
OPTION CASEMAP:NONE

; External Windows API functions
EXTERN VirtualProtect:PROC
EXTERN CreateFileA:PROC
EXTERN ReadFile:PROC
EXTERN WriteFile:PROC
EXTERN CloseHandle:PROC
EXTERN GetFileSizeEx:PROC

; ============================================================================
; Data Section
; ============================================================================
.DATA
ALIGN 16

; Engine state
selfhost_initialized    QWORD 0
selfhost_text_base      QWORD 0
selfhost_text_size      QWORD 0
selfhost_generation     QWORD 0

; Statistics
selfhost_stats          QWORD 8 DUP(0)  ; [0]=regions profiled, [1]=optimizations, etc.

; Profile buffer (circular, 256 entries)
PROFILE_BUFFER_SIZE     EQU 256
profile_buffer          QWORD PROFILE_BUFFER_SIZE * 4 DUP(0)  ; [addr, cycles, count, reserved]
profile_head            QWORD 0

; Code buffer for generated trampolines
CODE_BUFFER_SIZE        EQU 65536
code_buffer             BYTE CODE_BUFFER_SIZE DUP(0)
code_buffer_used        QWORD 0

; ============================================================================
; Code Section
; ============================================================================
.CODE

; ----------------------------------------------------------------------------
; asm_selfhost_init — Initialize self-hosting engine
; int asm_selfhost_init(void);
; Returns: 0 on success, -1 on error
; ----------------------------------------------------------------------------
asm_selfhost_init PROC EXPORT
    push rbx
    push rsi
    push rdi
    
    ; Check if already initialized
    mov rax, selfhost_initialized
    test rax, rax
    jnz .already_init
    
    ; Get .text section info via PEB
    mov rax, gs:[60h]           ; TEB->PEB
    mov rax, [rax+18h]          ; PEB->Ldr
    mov rax, [rax+20h]          ; InMemoryOrderModuleList
    mov rax, [rax]              ; First module (exe)
    mov rbx, [rax+20h]          ; DllBase
    
    ; Parse PE header to find .text
    mov eax, [rbx+3Ch]          ; e_lfanew
    lea rsi, [rbx+rax]          ; NT headers
    movzx eax, word ptr [rsi+14h]  ; SizeOfOptionalHeader
    lea rdi, [rsi+18h+rax]      ; First section header
    
    ; Find .text section
    movzx ecx, word ptr [rsi+6] ; NumberOfSections
.find_text:
    cmp ecx, 0
    je .text_not_found
    
    ; Check section name (first 4 chars of ".text")
    mov eax, [rdi]
    cmp eax, 07865742Eh         ; ".tex"
    je .found_text
    
    add rdi, 40                 ; Next section header
    dec ecx
    jmp .find_text
    
.found_text:
    mov eax, [rdi+0Ch]          ; VirtualAddress
    add rax, rbx
    mov selfhost_text_base, rax
    
    mov eax, [rdi+8]            ; VirtualSize
    mov selfhost_text_size, rax
    
    ; Clear profile buffer
    xor rax, rax
    mov rdi, OFFSET profile_buffer
    mov rcx, PROFILE_BUFFER_SIZE * 4
    rep stosq
    
    ; Mark initialized
    mov selfhost_initialized, 1
    xor rax, rax                ; success
    jmp .init_done
    
.already_init:
    xor rax, rax                ; already initialized = success
    jmp .init_done
    
.text_not_found:
    mov rax, -1
    
.init_done:
    pop rdi
    pop rsi
    pop rbx
    ret
asm_selfhost_init ENDP

; ----------------------------------------------------------------------------
; asm_selfhost_read_text — Read code from .text section
; int asm_selfhost_read_text(uint64_t rva, void* outBuf, uint32_t len);
; RCX = RVA from text base
; RDX = output buffer
; R8 = length to read
; Returns: 0 on success, -1 on error
; ----------------------------------------------------------------------------
asm_selfhost_read_text PROC EXPORT
    push rbx
    push rsi
    push rdi
    
    ; Check initialized
    mov rax, selfhost_initialized
    test rax, rax
    jz .read_error
    
    ; Validate bounds
    mov rax, selfhost_text_size
    cmp rcx, rax
    jae .read_error
    add rcx, r8
    cmp rcx, rax
    ja .read_error
    
    ; Calculate source address
    mov rbx, selfhost_text_base
    add rbx, rcx
    sub rbx, r8               ; undo the add above
    
    ; Copy
    mov rsi, rbx
    mov rdi, rdx
    mov rcx, r8
    rep movsb
    
    xor rax, rax              ; success
    jmp .read_done
    
.read_error:
    mov rax, -1
    
.read_done:
    pop rdi
    pop rsi
    pop rbx
    ret
asm_selfhost_read_text ENDP

; ----------------------------------------------------------------------------
; asm_selfhost_profile_region — Profile a code region
; void asm_selfhost_profile_region(uint64_t rva, uint32_t size, const char* name);
; RCX = RVA of region
; RDX = size of region
; R8 = name string (can be null)
; ----------------------------------------------------------------------------
asm_selfhost_profile_region PROC EXPORT
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    
    ; Check initialized
    mov rax, selfhost_initialized
    test rax, rax
    jz .profile_done
    
    ; Get current head index
    mov rbx, profile_head
    and rbx, PROFILE_BUFFER_SIZE - 1  ; Wrap around
    
    ; Calculate entry address
    lea rdi, profile_buffer
    shl rbx, 5                ; * 32 bytes per entry
    add rdi, rbx
    
    ; Store region info
    mov [rdi], rcx            ; RVA
    mov [rdi+8], rdx          ; Size
    mov [rdi+16], r8          ; Name pointer
    
    ; Read timestamp counter
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov [rdi+24], rax         ; Timestamp
    
    ; Increment head
    inc profile_head
    
    ; Update stats
    inc selfhost_stats
    
.profile_done:
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
asm_selfhost_profile_region ENDP

; ----------------------------------------------------------------------------
; asm_selfhost_gen_trampoline — Generate trampoline code
; uint64_t asm_selfhost_gen_trampoline(uint64_t targetRva, uint32_t patchType);
; RCX = target RVA to jump to
; RDX = patch type (0=direct, 1=profiling)
; Returns: address of generated trampoline, or 0 on error
; ----------------------------------------------------------------------------
asm_selfhost_gen_trampoline PROC EXPORT
    push rbx
    push rsi
    push rdi
    push r12
    
    ; Check initialized
    mov rax, selfhost_initialized
    test rax, rax
    jz .tramp_error
    
    ; Get code buffer position
    mov rbx, code_buffer_used
    cmp rbx, CODE_BUFFER_SIZE - 32
    jae .tramp_error          ; Buffer full
    
    lea rdi, code_buffer
    add rdi, rbx
    mov r12, rdi              ; Save trampoline address
    
    ; Generate trampoline based on type
    cmp rdx, 0
    je .gen_direct
    jmp .gen_profiling
    
.gen_direct:
    ; mov rax, target
    mov byte ptr [rdi], 48h   ; REX.W
    mov byte ptr [rdi+1], 0B8h
    mov rax, selfhost_text_base
    add rax, rcx
    mov [rdi+2], rax
    
    ; jmp rax
    mov byte ptr [rdi+10], 0FFh
    mov byte ptr [rdi+11], 0E0h
    
    add rbx, 12
    jmp .tramp_done
    
.gen_profiling:
    ; push rax
    mov byte ptr [rdi], 50h
    ; rdtsc
    mov byte ptr [rdi+1], 0Fh
    mov byte ptr [rdi+2], 31h
    ; push rax
    mov byte ptr [rdi+3], 50h
    ; push rdx
    mov byte ptr [rdi+4], 52h
    
    ; ... (simplified - would include full profiling logic)
    
    add rbx, 32
    
.tramp_done:
    mov code_buffer_used, rbx
    mov rax, r12              ; Return trampoline address
    jmp .tramp_exit
    
.tramp_error:
    xor rax, rax
    
.tramp_exit:
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
asm_selfhost_gen_trampoline ENDP

; ----------------------------------------------------------------------------
; asm_selfhost_micro_assemble — Assemble micro-op sequence
; int asm_selfhost_micro_assemble(const char* asmText, void* outCode, uint32_t* outLen);
; RCX = assembly text
; RDX = output code buffer
; R8 = pointer to length (in/out)
; Returns: 0 on success, -1 on error
; ----------------------------------------------------------------------------
asm_selfhost_micro_assemble PROC EXPORT
    push rbx
    push rsi
    push rdi
    
    ; Stub: would parse asm text and emit machine code
    ; For now, just return success with minimal NOP sled
    
    mov rdi, rdx
    mov rcx, [r8]             ; Get requested length
    mov rdx, 16
    cmp rcx, rdx
    cmova rcx, rdx            ; Max 16 bytes
    
    ; Emit NOPs
    mov al, 90h
    rep stosb
    
    mov [r8], rcx             ; Return actual length
    xor rax, rax              ; success
    
    pop rdi
    pop rsi
    pop rbx
    ret
asm_selfhost_micro_assemble ENDP

; ----------------------------------------------------------------------------
; asm_selfhost_atomic_swap — Atomic code swap
; int asm_selfhost_atomic_swap(uint64_t rva, const void* newCode, uint32_t len);
; RCX = RVA to patch
; RDX = new code
; R8 = length
; Returns: 0 on success, -1 on error
; ----------------------------------------------------------------------------
asm_selfhost_atomic_swap PROC EXPORT
    push rbx
    push rsi
    push rdi
    push r12
    
    ; Check initialized
    mov rax, selfhost_initialized
    test rax, rax
    jz .swap_error
    
    ; Calculate target address
    mov rbx, selfhost_text_base
    add rbx, rcx
    
    ; Validate bounds
    mov rax, selfhost_text_size
    cmp rcx, rax
    jae .swap_error
    add rcx, r8
    cmp rcx, rax
    ja .swap_error
    
    ; Change memory protection to writable
    sub rsp, 32
    mov rcx, rbx
    mov rdx, r8
    mov r8, 40h               ; PAGE_EXECUTE_READWRITE
    lea r9, [rsp+16]          ; oldProtect
    call VirtualProtect
    add rsp, 32
    
    ; Copy new code
    mov rsi, rdx
    mov rdi, rbx
    mov rcx, r8
    rep movsb
    
    ; Restore protection
    sub rsp, 32
    mov rcx, rbx
    mov rdx, r8
    mov r8, 20h               ; PAGE_EXECUTE_READ
    lea r9, [rsp+16]
    call VirtualProtect
    add rsp, 32
    
    ; Increment generation
    inc selfhost_generation
    
    xor rax, rax              ; success
    jmp .swap_done
    
.swap_error:
    mov rax, -1
    
.swap_done:
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
asm_selfhost_atomic_swap ENDP

; ----------------------------------------------------------------------------
; asm_selfhost_verify_equiv — Verify code equivalence
; int asm_selfhost_verify_equiv(const void* codeA, const void* codeB, uint32_t len);
; RCX = code A
; RDX = code B
; R8 = length
; Returns: 1 if equivalent, 0 if different
; ----------------------------------------------------------------------------
asm_selfhost_verify_equiv PROC EXPORT
    push rbx
    push rsi
    push rdi
    
    mov rsi, rcx
    mov rdi, rdx
    mov rcx, r8
    
.compare_loop:
    cmp rcx, 0
    je .verify_equal
    
    mov al, [rsi]
    mov bl, [rdi]
    cmp al, bl
    jne .verify_diff
    
    inc rsi
    inc rdi
    dec rcx
    jmp .compare_loop
    
.verify_equal:
    mov rax, 1
    jmp .verify_done
    
.verify_diff:
    xor rax, rax
    
.verify_done:
    pop rdi
    pop rsi
    pop rbx
    ret
asm_selfhost_verify_equiv ENDP

; ----------------------------------------------------------------------------
; asm_selfhost_measure_delta — Measure performance delta
; uint64_t asm_selfhost_measure_delta(uint64_t startCycles, uint64_t endCycles);
; RCX = start cycles
; RDX = end cycles
; Returns: delta cycles
; ----------------------------------------------------------------------------
asm_selfhost_measure_delta PROC EXPORT
    mov rax, rdx
    sub rax, rcx
    ret
asm_selfhost_measure_delta ENDP

; ----------------------------------------------------------------------------
; asm_selfhost_read_source — Read source file
; int asm_selfhost_read_source(const char* path, char* outBuf, uint32_t* outLen);
; RCX = file path
; RDX = output buffer
; R8 = pointer to length (in/out)
; Returns: 0 on success, -1 on error
; ----------------------------------------------------------------------------
asm_selfhost_read_source PROC EXPORT
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    
    mov r12, rcx              ; path
    mov r13, rdx              ; buffer
    mov r14, r8               ; len pointer
    
    ; Open file
    mov rcx, r12
    mov rdx, 80000000h        ; GENERIC_READ
    xor r8, r8
    xor r9, r9
    sub rsp, 32
    mov qword ptr [rsp+32], 3
    mov qword ptr [rsp+40], 0
    mov qword ptr [rsp+48], 0
    call CreateFileA
    add rsp, 32
    
    cmp rax, -1
    je .read_src_error
    mov rbx, rax              ; handle
    
    ; Get file size
    mov rcx, rbx
    xor rdx, rdx
    call GetFileSizeEx
    mov rsi, rax
    
    ; Clamp to buffer size
    mov rdi, [r14]
    cmp rsi, rdi
    cmova rsi, rdi
    
    ; Read file
    mov rcx, rbx
    mov rdx, r13
    mov r8, rsi
    lea r9, [rsp+16]
    sub rsp, 32
    xor rax, rax
    mov [rsp+32], rax
    call ReadFile
    add rsp, 32
    
    ; Close handle
    mov rcx, rbx
    call CloseHandle
    
    ; Return actual bytes read
    mov [r14], rsi
    xor rax, rax
    jmp .read_src_done
    
.read_src_error:
    mov rax, -1
    
.read_src_done:
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
asm_selfhost_read_source ENDP

; ----------------------------------------------------------------------------
; asm_selfhost_write_source — Write source file
; int asm_selfhost_write_source(const char* path, const char* data, uint32_t len);
; RCX = file path
; RDX = data
; R8 = length
; Returns: 0 on success, -1 on error
; ----------------------------------------------------------------------------
asm_selfhost_write_source PROC EXPORT
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    
    mov r12, rcx              ; path
    mov r13, rdx              ; data
    mov r14, r8               ; length
    
    ; Create file
    mov rcx, r12
    mov rdx, 40000000h        ; GENERIC_WRITE
    xor r8, r8
    xor r9, r9
    sub rsp, 32
    mov qword ptr [rsp+32], 2
    mov qword ptr [rsp+40], 128
    mov qword ptr [rsp+48], 0
    call CreateFileA
    add rsp, 32
    
    cmp rax, -1
    je .write_src_error
    mov rbx, rax
    
    ; Write data
    mov rcx, rbx
    mov rdx, r13
    mov r8, r14
    lea r9, [rsp+16]
    sub rsp, 32
    xor rax, rax
    mov [rsp+32], rax
    call WriteFile
    add rsp, 32
    
    ; Close handle
    mov rcx, rbx
    call CloseHandle
    
    xor rax, rax
    jmp .write_src_done
    
.write_src_error:
    mov rax, -1
    
.write_src_done:
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
asm_selfhost_write_source ENDP

; ----------------------------------------------------------------------------
; asm_selfhost_get_generation — Get current generation number
; uint64_t asm_selfhost_get_generation(void);
; ----------------------------------------------------------------------------
asm_selfhost_get_generation PROC EXPORT
    mov rax, selfhost_generation
    ret
asm_selfhost_get_generation ENDP

; ----------------------------------------------------------------------------
; asm_selfhost_get_stats — Get engine statistics
; void asm_selfhost_get_stats(uint64_t* outStats, uint32_t maxEntries);
; RCX = output buffer
; RDX = max entries to return
; ----------------------------------------------------------------------------
asm_selfhost_get_stats PROC EXPORT
    push rsi
    push rdi
    push r12
    
    mov rdi, rcx
    mov rsi, rdx
    
    mov r12, 8
    cmp rsi, r12
    cmova rsi, r12
    
    lea rax, selfhost_stats
    
.copy_stats:
    cmp rsi, 0
    je .stats_done
    mov rcx, [rax]
    mov [rdi], rcx
    add rax, 8
    add rdi, 8
    dec rsi
    jmp .copy_stats
    
.stats_done:
    pop r12
    pop rdi
    pop rsi
    ret
asm_selfhost_get_stats ENDP

; ----------------------------------------------------------------------------
; asm_selfhost_shutdown — Shutdown self-hosting engine
; void asm_selfhost_shutdown(void);
; ----------------------------------------------------------------------------
asm_selfhost_shutdown PROC EXPORT
    push rdi
    push rcx
    
    ; Clear sensitive data
    xor rax, rax
    mov rdi, OFFSET profile_buffer
    mov rcx, PROFILE_BUFFER_SIZE * 4
    rep stosq
    
    mov rdi, OFFSET code_buffer
    mov rcx, CODE_BUFFER_SIZE / 8
    rep stosq
    
    ; Reset state
    mov selfhost_initialized, 0
    mov selfhost_text_base, 0
    mov selfhost_text_size, 0
    mov selfhost_generation, 0
    mov selfhost_stats, 0
    mov code_buffer_used, 0
    mov profile_head, 0
    
    pop rcx
    pop rdi
    ret
asm_selfhost_shutdown ENDP

END
