; ==================================================================================
; SOVEREIGN CONFIGURATION SUBSTRATE - CORE SECURITY SUBSTRUCT
; File: Sovereign_Security.asm
; ==================================================================================

INCLUDE Sovereign_Security.inc

.code

;-----------------------------------------------------------------------------------
; Sovereign_Get_Hardware_ID
; Outputs: RAX = Monolithic 64-bit Hardware Fingerprint
; Preserved: RBX, RSI, RDI (Standard Windows x64 ABI Compliance)
;-----------------------------------------------------------------------------------
PUBLIC Sovereign_Get_Hardware_ID
Sovereign_Get_Hardware_ID PROC
    push rbx
    push rsi
    push rdi

    ; Leaf 1: Processor Topology & Base Instruction Capabilities
    mov eax, 1
    cpuid           ; Mutates EAX, EBX, ECX, EDX

    ; Shield upper 32 bits from implicit zero-extension destruction
    mov rsi, rax    ; Hold family/model mapping in RSI
    shl rsi, 32     ; Move up to the high dword slot
    mov eax, edx    ; Move base features into EAX (zeros upper 32-bits of RAX)
    or  rsi, rax    ; Symmetric merge of lower and upper execution descriptors

    ; Leaf 7: Structured Core Vector Extension Geometry (AVX-512 Pipeline State)
    xor ecx, ecx
    mov eax, 7
    cpuid           ; Mutates EAX, EBX, ECX, EDX

    mov eax, ebx    ; Isolate advanced feature execution lanes
    shl rax, 16
    xor rax, rsi    ; Complete full-width 64-bit deterministic HWID profiling

    pop rdi
    pop rsi
    pop rbx
    ret
Sovereign_Get_Hardware_ID ENDP

;-----------------------------------------------------------------------------------
; Sovereign_Verify_License
; Inputs:  RCX = Memory Pointer to target LICENSE_METADATA structure
; Outputs: RAX = 1 (Verification Succeeded), 0 (Hardware Signature Mismatch)
;-----------------------------------------------------------------------------------
PUBLIC Sovereign_Verify_License
Sovereign_Verify_License PROC
    push rbx
    push rsi
    push rdi
    push r12

    mov rsi, rcx    ; Cache memory context pointer inside non-volatile RSI

    ; Step 1: Query the local physical execution engine footprint
    call Sovereign_Get_Hardware_ID
    mov r12, rax    ; R12 = Absolute expected hardware signature target

    ; Step 2: Validate structural binding compatibility
    mov rax, [rsi].LICENSE_METADATA.HardwareID
    cmp rax, r12
    jne @ValidationFailureGate
    lfence          ; HARDWARE FENCE: Serialize pipeline to prevent Spectre v1 bypass

    ; Step 3: Recalculate token signature trace
    mov rcx, [rsi].LICENSE_METADATA.HardwareID
    mov rdx, [rsi].LICENSE_METADATA.FeatureMask
    call Sovereign_Generate_Key

    ; Step 4: Compare calculated parity against structure payload
    mov rbx, [rsi].LICENSE_METADATA.Signature

    ; Constant-time comparison check
    xor rax, rbx         ; If RAX == RBX, the result is 0
    lfence               ; SERIALIZATION BARRIER: Defeat Speculative Execution
    jnz @ValidationFailureGate

    mov rax, 1      ; Substrate integrity verified. Unlocking matrix array.
    jmp @VerificationExit

@ValidationFailureGate:
    xor rax, rax    ; Explicit structural invalidation signal across matrix nodes

@VerificationExit:
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
Sovereign_Verify_License ENDP

; ==============================================================================
; VERIFY_ARENA_INTEGRITY
; R15 = Context Pointer (Pinned)
; Returns: ZF=1 if VALID, ZF=0 if CORRUPT
; ==============================================================================
PUBLIC Verify_Arena_Integrity
Verify_Arena_Integrity PROC
    push rbx
    push rcx
    push rax

    ; 1. Load Arena Metadata from R15 Context
    mov rbx, [r15 + SOVEREIGN_FABRIC_CONTEXT.Tensor_Arena_Base]
    
    ; 2. Verify Magic Bytes (Quick Fail-Fast)
    mov rax, SOVEREIGN_MAGIC_BYTES
    cmp qword ptr [rbx + SOVEREIGN_ARENA_HEADER.Magic], rax
    jne @Integrity_Panic

    ; 3. Re-calculate CRC
    mov rdx, rbx               ; RDX = Pointer to header for the CRC routine
    call Compute_Arena_CRC 
    
    ; 4. Compare calculated CRC against stored Canary
    cmp rax, [rbx + SOVEREIGN_ARENA_HEADER.Canary]
    jne @Integrity_Panic

    pop rax
    pop rcx
    pop rbx
    ret

@Integrity_Panic:
    ; Immediate System Halt (Hardened Security Response)
    cli
    hlt
Verify_Arena_Integrity ENDP

;-----------------------------------------------------------------------------------
; Compute_Arena_CRC (Shared Subroutine)
; Inputs:  RDX = Pointer to SOVEREIGN_ARENA_HEADER
; Outputs: RAX = Calculated XOR Sum
;-----------------------------------------------------------------------------------
PUBLIC Compute_Arena_CRC
Compute_Arena_CRC PROC
    push rcx
    push rdx
    push rdi

    mov rcx, [rdx].SOVEREIGN_ARENA_HEADER.ArenaSize
    add rdx, SIZEOF SOVEREIGN_ARENA_HEADER ; Skip header, start at payload
    
    shr rcx, 3                 ; Calculate number of QWORDs
    xor rax, rax               ; Clear CRC accumulator
    test rcx, rcx
    jz @Done

@ChecksumLoop:
    xor rax, [rdx]             ; Incorporate QWORD into checksum
    add rdx, 8
    dec rcx
    jnz @ChecksumLoop

@Done:
    pop rdi
    pop rdx
    pop rcx
    ret
Compute_Arena_CRC ENDP

; ==============================================================================
; FABRIC_SAFE_INIT
; Target: 0x100000 (Static Base)
; ==============================================================================
PUBLIC Fabric_Safe_Init
Fabric_Safe_Init PROC
    push rbx
    push rdi
    push rcx
    push rax

    ; 1. Load targets from R15
    mov rbx, [r15].SOVEREIGN_FABRIC_CONTEXT.Tensor_Arena_Base
    mov rcx, [r15].SOVEREIGN_FABRIC_CONTEXT.Tensor_Arena_Size
    
    ; 2. Zero-out the entire arena (Fast REP STOSQ)
    mov rdi, rbx            ; Dest
    xor rax, rax            ; Fill with 0
    mov rdx, rcx            ; Save size for header
    shr rcx, 3              ; QWORD count (Bytes / 8)
    rep stosq               ; Wipe memory clean

    ; 3. Write Arena Header
    mov rax, SOVEREIGN_MAGIC_BYTES
    mov qword ptr [rbx + SOVEREIGN_ARENA_HEADER.Magic], rax
    mov qword ptr [rbx + SOVEREIGN_ARENA_HEADER.Version], SOVEREIGN_SCHEMA_VER
    mov qword ptr [rbx + SOVEREIGN_ARENA_HEADER.ArenaSize], rdx
    
    ; 4. Calculate initial Checksum
    mov rdx, rbx            ; Pass arena base to CRC calculator
    call Compute_Arena_CRC  ; Returns CRC in RAX
    mov [rbx + SOVEREIGN_ARENA_HEADER.Canary], rax 

    pop rax
    pop rcx
    pop rdi
    pop rbx
    ret
Fabric_Safe_Init ENDP

;-----------------------------------------------------------------------------------
; Sovereign_Rotate_Signature
; Inputs:  R15 = Pointer to SOVEREIGN_FABRIC_CONTEXT
; Outputs: Updates Rolling_Signature utilizing the hardened Generate_Key primitive.
;-----------------------------------------------------------------------------------
PUBLIC Sovereign_Rotate_Signature
Sovereign_Rotate_Signature PROC
    push rax
    push rbx
    push rcx
    push rdx
    push r11

    ; 1. Harvest Fresh Entropy (Try RDRAND first)
    rdrand rax
    jnc @UseInternalSeed       ; If RDRAND fails, fallback
    mov [r15].SOVEREIGN_FABRIC_CONTEXT.Rotation_Salt, rax

@UseInternalSeed:
    ; 2. Derive next signature segment
    mov rcx, [r15].SOVEREIGN_FABRIC_CONTEXT.Rolling_Signature
    mov rdx, [r15].SOVEREIGN_FABRIC_CONTEXT.Rotation_Salt
    xor rdx, [r15].SOVEREIGN_FABRIC_CONTEXT.Fabric_Status 
    
    call Sovereign_Generate_Key
    
    ; 3. Commit the new rotational secret
    mov [r15].SOVEREIGN_FABRIC_CONTEXT.Rolling_Signature, rax

    pop r11
    pop rdx
    pop rcx
    pop rbx
    pop rax
    ret
Sovereign_Rotate_Signature ENDP

;-----------------------------------------------------------------------------------
; Compute_Result_MAC
; Generates a MAC for the task result using the current Rolling_Signature
; Inputs:  R14 = Base Pointer to Result Buffer
;          R13 = Data Size (in QWORDS)
;          R12 = Rolling_Signature (Secret Key)
; Outputs: RAX = Computed MAC
;-----------------------------------------------------------------------------------
PUBLIC Compute_Result_MAC
Compute_Result_MAC PROC
    push rbx
    push rcx
    
    mov rax, r12        ; Start with the secret key
    xor rcx, rcx        ; Loop index
    test r13, r13
    jz @Done
    
@MAC_Loop:
    mov rbx, [r14 + rcx*8] ; Load result qword
    xor rax, rbx           ; Mix data with rolling state
    rol rax, 7             ; Rotate for bit-diffusion
    inc rcx
    cmp rcx, r13
    jl @MAC_Loop
      
@Done:
    pop rcx
    pop rbx
    ret
Compute_Result_MAC ENDP
      
;-----------------------------------------------------------------------------------
; Verify_Task_Receipt
; Inputs:  R14 = Buffer Pointer, R13 = Size (QWORDS), R12 = Signature
; Outputs: RAX = 1 (Valid), 0 (Breach Detected)
;-----------------------------------------------------------------------------------
PUBLIC Verify_Task_Receipt
Verify_Task_Receipt PROC
    push rbx
    
    ; 1. Calculate MAC on existing data
    call Compute_Result_MAC
    
    ; 2. Compare against appended MAC (appended after r13 qwords)
    mov rbx, [r14 + r13*8] 
    xor rax, rbx
    lfence              ; Serialization barrier
    jnz @Invalid
    
    mov rax, 1
    jmp @Exit

@Invalid:
    xor rax, rax

@Exit:
    pop rbx
    ret
Verify_Task_Receipt ENDP

; ==============================================================================
; SOVEREIGN_HARVEST_ENTROPY
; R15 = Global Security Context
; ==============================================================================
PUBLIC Sovereign_Harvest_Entropy
Sovereign_Harvest_Entropy PROC
    push rcx
    push rdx
    push rbx

    mov rcx, 16 ; Fill 16 QWORDs (Entropy_Pool size)
    lea rbx, [r15 + SOVEREIGN_SECURITY_CONTEXT.Entropy_Pool]

@Entropy_Loop:
    ; 1. Attempt RDRAND (Hardware RNG)
    rdrand rax
    jc @Store_Entropy   ; Carry set if success

    ; 2. Fallback: Use RDTSC (Clock Noise) + Junk Register State
    rdtsc
    shl rax, 32
    rdtscp
    or rax, rdx

@Store_Entropy:
    mov [rbx], rax
    add rbx, 8
    loop @Entropy_Loop

    pop rbx
    pop rdx
    pop rcx
    ret
Sovereign_Harvest_Entropy ENDP

; ==============================================================================
; SOVEREIGN_REFRESH_SIGNATURE
; Updates the Dynamic_Signature based on current Entropy_Pool
; ==============================================================================
PUBLIC Sovereign_Refresh_Signature
Sovereign_Refresh_Signature PROC
    lea rsi, [r15 + SOVEREIGN_SECURITY_CONTEXT.Entropy_Pool]
    lea rdi, [r15 + SOVEREIGN_SECURITY_CONTEXT.Dynamic_Signature]
    
    ; Simple XOR-Fold: Hash the entropy into the signature
    mov rcx, 4 ; 4 QWORDs in the signature
@Hash_Loop:
    mov rax, [rsi + rcx*8]
    xor [rdi + rcx*8], rax
    loop @Hash_Loop
    ret
Sovereign_Refresh_Signature ENDP

END