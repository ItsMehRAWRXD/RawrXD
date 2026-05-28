; ==================================================================================
; SOVEREIGN LOADER CORE
; File: Sovereign_Loader.asm
; Role: Deterministic GGUF Loader & Zero-Drift Registry Insertion
; ==================================================================================

include Sovereign_Common.inc
include Sovereign_FrameABI.inc
include Sovereign_GGUF_Schema_Runtime.inc

EXTERN Sovereign_Skip_KV_Pairs:PROC
EXTERN Sovereign_Registry_Insert:PROC

.CODE

PUBLIC Sovereign_Registry_Hash
Sovereign_Registry_Hash PROC
    mov rax, 14695981039346656037
    mov r8, 1099511628211
@@HashLoop:
    test rdx, rdx
    jz @@Done
    movzx r9, byte ptr [rcx]
    xor rax, r9
    imul rax, r8              ; Fixed RDX:RAX clobber bug
    inc rcx
    dec rdx
    jmp @@HashLoop
@@Done:
    ret
Sovereign_Registry_Hash ENDP

PUBLIC Sovereign_Loader_Parse
Sovereign_Loader_Parse PROC
    ENTER_FRAME
    
    mov rsi, rcx              ; File mapped pointer
    
    ; Verify Magic
    mov eax, [rsi]
    cmp eax, GGUF_MAGIC
    jne @@Fail
    
    ; Load Headers
    mov r12, [rsi + 8]        ; R12 = Tensor Count
    mov rdi, [rsi + 16]       ; RDI = KV Count
    add rsi, 24               ; Advance past primary header
    
    ; Deterministic KV Skip
    call Sovereign_Skip_KV_Pairs
    
    ; Tensor Insertion Loop
    test r12, r12
    jz @@Success

@@TensorLoop:
    mov r14, [rsi]            ; R14 = Name Length
    add rsi, 8                ; Advance to name string
    
    mov rcx, rsi              ; RCX = String Ptr
    mov rdx, r14              ; RDX = String Length
    call Sovereign_Registry_Hash
    mov r13, rax              ; R13 = Hash Result
    
    add rsi, r14              ; Advance past string
    
    mov ebx, [rsi]            ; EBX = Dimensions (DWORD)
    add rsi, 4
    
    ; Skip dimension array (QWORD * dimensions)
    mov eax, ebx
    shl rax, 3
    add rsi, rax
    
    mov ebx, [rsi]            ; EBX = Tensor Type (DWORD)
    add rsi, 4
    
    mov r15, [rsi]            ; R15 = Tensor Offset (QWORD)
    add rsi, 8
    
    ; Insert into Registry (R13 = Hash, R15 = Offset)
    mov rcx, r13
    mov rdx, r15
    call Sovereign_Registry_Insert
    
    dec r12
    jnz @@TensorLoop

@@Success:
    mov rax, 1
    EXIT_FRAME
    ret

@@Fail:
    xor rax, rax
    EXIT_FRAME
    ret
Sovereign_Loader_Parse ENDP

END
