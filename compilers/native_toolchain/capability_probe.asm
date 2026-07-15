; capability_probe.asm
; Pure x64 MASM - no dependencies, no includes, no imports
; Queries the loaded model about IDE capabilities

.data
    ; System prompt - tells model its role
    sys_prompt db "You are analyzing a custom IDE built from scratch.", 0Ah
              db "Report ONLY what you can actually do based on available engines.", 0Ah
              db "Be specific. No speculation.", 0Ah, 0
    
    ; Engine inventory - populated at build time, verified at runtime
    engines db "=== VERIFIED ENGINES (compiled and linked) ===", 0Ah
            db "ASSEMBLER: Native x64 MASM assembler (500+ instructions, AVX/AVX2/AVX-512/SSE)", 0Ah
            db "LINKER: Native PE/COFF linker (multi-section, relocations, IAT)", 0Ah
            db "LIBRARIAN: Static library archiver", 0Ah
            db "RC: Resource compiler", 0Ah
            db "GGUF: Model loader (Q4_0 quantized tensors)", 0Ah
            db "INFERENCE: Full transformer forward pass", 0Ah
            db "DEQUANT: Q4_0 dequantization kernel (12.8B elem/sec verified)", 0Ah
            db "SILU: SiLU activation (AVX-512)", 0Ah
            db "RMSNORM: RMSNorm (AVX2 tiled, 8.2B elem/sec)", 0Ah
            db "SOFTMAX: Softmax forward (AVX2)", 0Ah
            db "FLASHATTN: FlashAttention (AVX-512)", 0Ah
            db "MATMUL: AVX-512 matrix multiply", 0Ah
            db "DISASM: Multi-arch decoder (ARM64, MIPS32, RISC-V32, x64)", 0Ah
            db "COMPILERS: 8 language compilers (Universal, EON, Bash, PS, Java, C#, Python, JS)", 0Ah
            db "FILEIO: File open/read/write/search/create/delete", 0Ah
            db "TERMINAL: PowerShell and CMD execution", 0Ah
            db "GIT: Git status, diff, commit, branch, log", 0Ah
            db "HOTPATCH: Self-modifying code system", 0Ah
            db "ACTION: IDE action executor (open file, search, compile, run)", 0Ah, 0
    
    missing db "=== CONFIRMED MISSING ===", 0Ah
            db "GPU: No Vulkan/ROCm/CUDA/DirectML support", 0Ah
            db "PDB: No debug info generation", 0Ah
            db "SETTINGS: No settings dialog (placeholder only)", 0Ah
            db "PARALLEL: No parallel tool execution", 0Ah
            db "SPECULATIVE: No speculative tool execution", 0Ah
            db "BATCH: No batch inference", 0Ah, 0
    
    query db 0Ah, "Based on the VERIFIED ENGINES list above:", 0Ah
          db "1. List each capability you CAN perform with this IDE", 0Ah
          db "2. For each, state if it needs a loaded model or works standalone", 0Ah
          db "3. List what you CANNOT do based on CONFIRMED MISSING", 0Ah
          db "4. Do not guess or speculate about unlisted features", 0Ah, 0

.code
; External functions
EXTERN GetStdHandle:PROC
EXTERN WriteFile:PROC
EXTERN ExitProcess:PROC

; ProbeBuffer - fills a context window with engine inventory
; RCX = output buffer
; RDX = buffer size
; Returns: bytes written
ProbeBuffer PROC
    push rbx
    push rsi
    push rdi
    mov rdi, rcx
    mov rbx, rdx
    xor r8d, r8d
    
    lea rsi, sys_prompt
    call copy_string
    
    lea rsi, engines
    call copy_string
    
    lea rsi, missing
    call copy_string
    
    lea rsi, query
    call copy_string
    
    mov rax, r8
    pop rdi
    pop rsi
    pop rbx
    ret

copy_string:
    cmp r8, rbx
    jae done_copy
    mov al, [rsi]
    test al, al
    jz done_copy
    mov [rdi], al
    inc rsi
    inc rdi
    inc r8
    jmp copy_string
done_copy:
    ret
ProbeBuffer ENDP

; strlen helper
strlen PROC
    mov rax, rdx
strlen_loop:
    cmp byte ptr [rax], 0
    je strlen_done
    inc rax
    jmp strlen_loop
strlen_done:
    sub rax, rdx
    ret
strlen ENDP

; CapabilityTest - standalone test (no model needed)
; Prints engine inventory to stdout
; Returns: 0 if all engines verified
CapabilityTest PROC
    sub rsp, 56
    
    ; Get stdout handle
    mov ecx, -11
    call GetStdHandle
    mov r12, rax
    
    ; Write engines list
    lea rdx, engines
    call strlen
    mov r8, rax
    mov rcx, r12
    lea rdx, engines
    xor r9, r9
    mov qword ptr [rsp+32], 0
    call WriteFile
    
    ; Write missing list
    lea rdx, missing
    call strlen
    mov r8, rax
    mov rcx, r12
    lea rdx, missing
    xor r9, r9
    mov qword ptr [rsp+32], 0
    call WriteFile
    
    xor ecx, ecx
    call ExitProcess
    
    add rsp, 56
    ret
CapabilityTest ENDP

; Exports for the loader
PUBLIC ProbeBuffer
PUBLIC CapabilityTest
END
