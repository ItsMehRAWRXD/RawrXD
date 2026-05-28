; =====================================================================================
; SOVEREIGN ENGINE - CONFIGURATION STORE (KV REGISTRY)
; SUBSYSTEM: ZERO-DEP HASHED LOOKUP TABLE
; ARCHITECTURE: X86-64 (MASM64)
; CODENAME: CONFIG_REGISTRY v1.0.0
; =====================================================================================

.DATA
    ; Configuration Type Constants
    CONFIG_TYPE_NONE    EQU 0
    CONFIG_TYPE_INT     EQU 1
    CONFIG_TYPE_BOOL    EQU 2
    CONFIG_TYPE_STRING  EQU 3
    CONFIG_TYPE_FLOAT   EQU 4
    CONFIG_TYPE_ARRAY   EQU 5

    ; FNV-1a 64-bit Constants
    FNV_OFFSET_BASIS    EQU 0CBF29CE484222325h
    FNV_PRIME           EQU 00000100000001B3h

.CODE

; =====================================================================================
; STRUCTURE: CONFIG ENTRY
; =====================================================================================
SOVEREIGN_CONFIG_ENTRY STRUCT
    Hash            QWORD ?         ; FNV-1a 64-bit hash of key
    KeyPtr          QWORD ?         ; Pointer to key string in arena (optional info)
    KeyLen          QWORD ?         ; Length of key string
    
    ValType         DWORD ?         ; CONFIG_TYPE_*
    Flags           DWORD ?         ; Reserved for access flags (read-only, etc)
    
    ValueInt        QWORD ?         ; Stores INT/BOOL/FLOAT directly
    ValuePtr        QWORD ?         ; For STRING/ARRAY: pointer to data in arena
    ValueLen        QWORD ?         ; For STRING/ARRAY: length of data
    
    Next            QWORD ?         ; Collision pointer
SOVEREIGN_CONFIG_ENTRY ENDS

; =====================================================================================
; STRUCTURE: CONFIG STORE
; =====================================================================================
SOVEREIGN_CONFIG_STORE STRUCT
    BucketCount     QWORD ?         ; Number of buckets (must be power of 2)
    BucketMask      QWORD ?         ; BucketCount - 1
    Buckets         QWORD ?         ; Pointer to array of QWORDs (entry pointers)
    
    ArenaBase       QWORD ?         ; Base of allocation arena
    ArenaOffset     QWORD ?         ; Current allocation cursor
    ArenaSize       QWORD ?         ; Total arena capacity
SOVEREIGN_CONFIG_STORE ENDS

; =====================================================================================
; API: Sovereign_Hash_Key (FNV-1a 64-bit)
; INPUT:  RCX = string pointer
;         RDX = string length
; OUTPUT: RAX = 64-bit hash
; =====================================================================================
Sovereign_Hash_Key PROC
    push rsi
    push rcx
    push rdx
    
    mov rax, FNV_OFFSET_BASIS
    mov rsi, rcx
    
hash_loop:
    test rdx, rdx
    jz hash_done
    movzx r8, byte ptr [rsi]
    xor rax, r8
    mov r9, FNV_PRIME
    mul r9                          ; RAX = RAX * FNV_PRIME, RDX = clobbered
    inc rsi
    ; Recalculate RDX? No, we need to preserve it.
    ; Let's use the pushed RDX on stack for loop control.
    mov r8, qword ptr [rsp]         ; R8 = original RDX
    dec r8
    mov qword ptr [rsp], r8
    mov rdx, r8                     ; Restore RDX for next loop or exit
    jmp hash_loop

hash_done:
    pop rdx
    pop rcx
    pop rsi
    ret
Sovereign_Hash_Key ENDP

; =====================================================================================
; API: Sovereign_Config_Init
; INPUT:  RCX = store pointer
;         RDX = arena pointer
;         R8  = arena size
;         R9  = bucket count (power of 2)
; =====================================================================================
Sovereign_Config_Init PROC
    push rdi
    mov qword ptr [rcx + SOVEREIGN_CONFIG_STORE.ArenaBase], rdx
    mov qword ptr [rcx + SOVEREIGN_CONFIG_STORE.ArenaSize], r8
    mov qword ptr [rcx + SOVEREIGN_CONFIG_STORE.ArenaOffset], 0
    mov qword ptr [rcx + SOVEREIGN_CONFIG_STORE.BucketCount], r9
    
    lea rax, [r9 - 1]
    mov qword ptr [rcx + SOVEREIGN_CONFIG_STORE.BucketMask], rax
    
    ; Allocate bucket array from start of arena
    mov qword ptr [rcx + SOVEREIGN_CONFIG_STORE.Buckets], rdx
    
    ; Calculate bucket memory size: count * 8
    mov r10, r9
    shl r10, 3
    mov qword ptr [rcx + SOVEREIGN_CONFIG_STORE.ArenaOffset], r10
    
    ; Zero-initialize buckets
    mov rdi, rdx
    mov rcx, r9                      ; Count of QWORDs
    xor rax, rax
    rep stosq
    
    xor rax, rax
    pop rdi
    ret
Sovereign_Config_Init ENDP

; =====================================================================================
; HELPER: Arena_Alloc
; INPUT:  RCX = store pointer
;         RDX = size needed
; OUTPUT: RAX = pointer to allocated memory or 0
; =====================================================================================
Arena_Alloc PROC
    mov r8, qword ptr [rcx + SOVEREIGN_CONFIG_STORE.ArenaOffset]
    mov r9, qword ptr [rcx + SOVEREIGN_CONFIG_STORE.ArenaSize]
    
    ; Align size to 8 bytes
    add rdx, 7
    and rdx, -8
    
    mov rax, r8
    add rax, rdx
    cmp rax, r9
    jg alloc_fail
    
    mov qword ptr [rcx + SOVEREIGN_CONFIG_STORE.ArenaOffset], rax
    mov rax, qword ptr [rcx + SOVEREIGN_CONFIG_STORE.ArenaBase]
    add rax, r8
    ret
    
alloc_fail:
    xor rax, rax
    ret
Arena_Alloc ENDP

; =====================================================================================
; API: Sovereign_Config_Put
; INPUT:  RCX = store pointer
;         RDX = Entry Template (partially filled)
;         R8  = Key Pointer
;         R9  = Key Length
; =====================================================================================
Sovereign_Config_Put PROC
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    sub rsp, 32

    mov rbx, rcx                    ; RBX = store
    mov r12, rdx                    ; R12 = Template entry info
    mov r13, r8                     ; R13 = Key Ptr (src)
    mov r14, r9                     ; R14 = Key Len

    ; 1. Hash the key
    mov rcx, r13
    mov rdx, r14
    call Sovereign_Hash_Key
    mov rdx, rax                    ; RDX = Hash

    ; 2. Check if already exists (O(1) lookup check)
    mov rcx, rbx
    call Sovereign_Config_Get_Internal
    test rax, rax
    jnz put_update                  ; If exists, update existing

    ; 3. Allocate new entry
    mov rcx, rbx
    mov rdx, SIZEOF SOVEREIGN_CONFIG_ENTRY
    call Arena_Alloc
    test rax, rax
    jz put_fail
    mov rsi, rax                    ; RSI = New Entry pointer

    ; 4. Copy Key into Arena for stability
    mov rcx, rbx
    mov rdx, r14
    call Arena_Alloc
    test rax, rax
    jz put_fail
    mov rdi, rax                    ; RDI = Key destination in arena
    mov qword ptr [rsi + SOVEREIGN_CONFIG_ENTRY.KeyPtr], rdi
    mov qword ptr [rsi + SOVEREIGN_CONFIG_ENTRY.KeyLen], r14
    
    mov rcx, r14
    mov r11, rsi                    ; Save rsi
    mov rsi, r13                    ; Source key
    rep movsb
    mov rsi, r11                    ; Restore rsi

    ; 5. Update Metadata
    mov rcx, rcx                    ; RCX is now 0 from rep movsb
    mov rcx, r13
    mov rdx, r14
    call Sovereign_Hash_Key         ; Recalc hash (easier than preserving)
    mov qword ptr [rsi + SOVEREIGN_CONFIG_ENTRY.Hash], rax

    ; 6. Copy Value data based on type
    mov eax, dword ptr [r12 + SOVEREIGN_CONFIG_ENTRY.ValType]
    mov dword ptr [rsi + SOVEREIGN_CONFIG_ENTRY.ValType], eax
    
    cmp eax, CONFIG_TYPE_STRING
    je put_string
    cmp eax, CONFIG_TYPE_ARRAY
    je put_array
    
    ; Direct value (INT/BOOL/FLOAT)
    mov rax, qword ptr [r12 + SOVEREIGN_CONFIG_ENTRY.ValueInt]
    mov qword ptr [rsi + SOVEREIGN_CONFIG_ENTRY.ValueInt], rax
    jmp put_finalize

put_string:
    mov rdx, qword ptr [r12 + SOVEREIGN_CONFIG_ENTRY.ValueLen]
    mov qword ptr [rsi + SOVEREIGN_CONFIG_ENTRY.ValueLen], rdx
    mov rcx, rbx
    call Arena_Alloc
    test rax, rax
    jz put_fail
    mov qword ptr [rsi + SOVEREIGN_CONFIG_ENTRY.ValuePtr], rax
    
    ; Copy internal string bytes
    mov rdi, rax
    mov r11, rsi                    ; Save rsi (entry pointer)
    mov rsi, qword ptr [r12 + SOVEREIGN_CONFIG_ENTRY.ValuePtr]
    mov rcx, qword ptr [r12 + SOVEREIGN_CONFIG_ENTRY.ValueLen]
    rep movsb
    mov rsi, r11                    ; Restore rsi
    jmp put_finalize

put_array:
    ; (Array support logic here later)
    jmp put_finalize

put_update:
    mov rsi, rax                    ; RSI = Existing Entry
    ; Logic to update existing entry value (usually not needed for static config)
    jmp put_finalize

put_finalize:
    ; 7. Link into bucket
    mov rax, qword ptr [rsi + SOVEREIGN_CONFIG_ENTRY.Hash]
    and rax, qword ptr [rbx + SOVEREIGN_CONFIG_STORE.BucketMask]
    
    mov rdx, qword ptr [rbx + SOVEREIGN_CONFIG_STORE.Buckets]
    lea rdx, [rdx + rax * 8]        ; RDX = pointer to bucket entry
    
    mov rcx, qword ptr [rdx]        ; RCX = current head
    mov qword ptr [rsi + SOVEREIGN_CONFIG_ENTRY.Next], rcx
    mov qword ptr [rdx], rsi

    xor rax, rax
    jmp put_done

put_fail:
    mov rax, -1

put_done:
    add rsp, 32
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
Sovereign_Config_Put ENDP

; =====================================================================================
; HELPER: Sovereign_Config_Get_Internal
; INPUT:  RBX = store
;         RDX = Hash
; OUTPUT: RAX = Entry pointer or 0
; =====================================================================================
Sovereign_Config_Get_Internal PROC
    mov rax, rdx
    and rax, qword ptr [rbx + SOVEREIGN_CONFIG_STORE.BucketMask]
    
    mov r8, qword ptr [rbx + SOVEREIGN_CONFIG_STORE.Buckets]
    mov rax, qword ptr [r8 + rax * 8] ; RAX = head of bucket
    
get_loop:
    test rax, rax
    jz get_none
    cmp rdx, qword ptr [rax + SOVEREIGN_CONFIG_ENTRY.Hash]
    je get_found
    mov rax, qword ptr [rax + SOVEREIGN_CONFIG_ENTRY.Next]
    jmp get_loop

get_found:
    ret
get_none:
    xor rax, rax
    ret
Sovereign_Config_Get_Internal ENDP

; =====================================================================================
; API: Sovereign_Config_Get
; INPUT:  RCX = store pointer
;         RDX = Key Pointer
;         R8  = Key Length
; OUTPUT: RAX = Entry pointer or 0
; =====================================================================================
Sovereign_Config_Get PROC
    push rbx
    sub rsp, 32
    
    mov rbx, rcx
    mov rcx, rdx
    mov rdx, r8
    call Sovereign_Hash_Key
    
    mov rdx, rax
    call Sovereign_Config_Get_Internal
    
    add rsp, 32
    pop rbx
    ret
Sovereign_Config_Get ENDP

END
