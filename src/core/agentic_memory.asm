; ============================================================================
; agentic_memory.asm — RawrXD Agentic Memory Layer (RAG Foundation)
; ============================================================================;
; Provides a simple key-value memory store for the agent.
; Features:
;   - Fixed-size memory slots (power-of-2 for fast indexing)
;   - Content-addressable storage with simple hash-based lookup
;   - Integration with Tool Registry via SAVE_MEMORY and RECALL_MEMORY tools
;
; Build: ml64.exe /c agentic_memory.asm
; Link:  link.exe agentic_memory.obj [other objs] /OUT:AgenticUnified.exe
;
; ============================================================================;

; ============================================================================
; External Imports
; ============================================================================;

extern GetTickCount:proc
extern RtlZeroMemory:proc
extern RtlCopyMemory:proc
extern RtlCompareMemory:proc

; ============================================================================
; Constants
; ============================================================================;

; Memory configuration
MEMORY_SLOT_COUNT       equ 256         ; 256 slots (power-of-2)
MEMORY_SLOT_SIZE        equ 1024        ; 1KB per slot
MEMORY_KEY_SIZE         equ 64          ; 64 bytes for key
MEMORY_TOTAL_SIZE       equ MEMORY_SLOT_COUNT * MEMORY_SLOT_SIZE

; Hash constants (FNV-1a inspired)
HASH_OFFSET_BASIS       equ 14695981039346656037
HASH_PRIME              equ 1099511628211

; Status codes
MEM_STATUS_SUCCESS      equ 0
MEM_STATUS_FULL         equ 1
MEM_STATUS_NOT_FOUND    equ 2
MEM_STATUS_INVALID_KEY  equ 3
MEM_STATUS_INVALID_DATA equ 4

; ============================================================================
; Data Section
; ============================================================================;

.data

; Memory arena - 256KB total
ALIGN 16
memory_arena:
    db MEMORY_TOTAL_SIZE dup(0)

; Slot metadata - tracks which slots are used
ALIGN 16
slot_used:
    db MEMORY_SLOT_COUNT dup(0)

; Slot timestamps for LRU eviction
slot_timestamp:
    dq MEMORY_SLOT_COUNT dup(0)

; Current timestamp counter
current_timestamp       dq 0

; Statistics
mem_store_count         dq 0
mem_recall_count        dq 0
mem_eviction_count      dq 0

; ============================================================================
; Code Section
; ============================================================================;

.code

; ============================================================================
; Hash Function (FNV-1a variant)
; uint64_t HashKey(const void* key, size_t len)
; RCX = key pointer, RDX = length
; Returns: RAX = hash value
; ============================================================================;
HashKey proc
    push rbx
    push rdi
    push rsi
    
    mov rsi, rcx            ; RSI = key
    mov rdi, rdx            ; RDI = length
    mov rax, HASH_OFFSET_BASIS  ; RAX = hash
    
    test rdi, rdi
    jz @@done
    
@@loop:
    movzx ebx, byte ptr [rsi]
    xor rax, rbx
    mov rbx, HASH_PRIME
    mul rbx                 ; RDX:RAX = RAX * PRIME (keep low 64 bits)
    inc rsi
    dec rdi
    jnz @@loop
    
@@done:
    pop rsi
    pop rdi
    pop rbx
    ret
HashKey endp

; ============================================================================
; Find Slot by Key
; int FindSlot(const void* key, size_t key_len)
; RCX = key, RDX = key_len
; Returns: RAX = slot index (-1 if not found)
; ============================================================================;
FindSlot proc
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 40
    
    mov r12, rcx            ; R12 = key
    mov r13, rdx            ; R13 = key_len
    
    ; Compute hash
    mov rcx, r12
    mov rdx, r13
    call HashKey
    
    ; Start at hash % MEMORY_SLOT_COUNT
    and eax, 0FFh           ; EAX = hash % 256
    mov r14d, eax           ; R14 = starting slot
    mov r15d, 0             ; R15 = probe count
    
@@probe:
    ; Check if we've probed all slots
    cmp r15d, MEMORY_SLOT_COUNT
    jge @@not_found
    
    ; Compute current slot index
    mov eax, r14d
    add eax, r15d
    and eax, 0FFh           ; Wrap around with power-of-2 mask
    mov ebx, eax            ; EBX = current slot
    
    ; Check if slot is used
    movzx ecx, byte ptr [slot_used + rbx]
    test ecx, ecx
    jz @@next_probe         ; Empty slot, skip
    
    ; Compare keys
    mov rcx, r12
    mov rax, rbx
    imul rax, MEMORY_SLOT_SIZE
    lea rdx, [memory_arena + rax]
    mov r8, r13
    cmp r8, MEMORY_KEY_SIZE
    jbe @@key_len_ok
    mov r8, MEMORY_KEY_SIZE
@@key_len_ok:
    call RtlCompareMemory
    cmp rax, r8             ; Check if all bytes matched
    jne @@next_probe        ; Keys don't match
    
    ; Found!
    mov eax, ebx
    jmp @@done
    
@@next_probe:
    inc r15d
    jmp @@probe
    
@@not_found:
    mov eax, -1
    
@@done:
    add rsp, 40
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
FindSlot endp

; ============================================================================
; Find Free Slot (with LRU eviction)
; int FindFreeSlot(void)
; Returns: RAX = slot index
; ============================================================================;
FindFreeSlot proc
    push rbx
    push r12
    push r13
    sub rsp, 40
    
    ; First pass: find unused slot
    xor ebx, ebx
@@find_unused:
    cmp ebx, MEMORY_SLOT_COUNT
    jge @@need_eviction
    
    movzx eax, byte ptr [slot_used + rbx]
    test eax, eax
    jz @@found
    
    inc ebx
    jmp @@find_unused
    
@@need_eviction:
    ; Find oldest slot (LRU eviction)
    mov r12, -1             ; R12 = oldest timestamp
    mov r13, 0              ; R13 = oldest slot
    xor ebx, ebx
@@find_oldest:
    cmp ebx, MEMORY_SLOT_COUNT
    jge @@evict
    
    mov rax, [slot_timestamp + rbx * 8]
    cmp rax, r12
    jae @@not_older
    mov r12, rax
    mov r13, rbx
@@not_older:
    inc ebx
    jmp @@find_oldest
    
@@evict:
    mov rbx, r13
    inc qword ptr [mem_eviction_count]
    
@@found:
    mov eax, ebx
    
@@done:
    add rsp, 40
    pop r13
    pop r12
    pop rbx
    ret
FindFreeSlot endp

; ============================================================================
; Memory Store
; int Memory_Store(const void* key, size_t key_len, const void* data, size_t data_len)
; RCX = key, RDX = key_len, R8 = data, R9 = data_len
; Returns: RAX = status code
; ============================================================================;
Memory_Store proc
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 56
    
    ; Save arguments
    mov r12, rcx            ; R12 = key
    mov r13, rdx            ; R13 = key_len
    mov r14, r8             ; R14 = data
    mov r15, r9             ; R15 = data_len
    
    ; Validate inputs
    test r12, r12
    jz @@invalid_key
    test r13, r13
    jz @@invalid_key
    test r14, r14
    jz @@invalid_data
    test r15, r15
    jz @@invalid_data
    
    ; Check data size (must fit in slot after key)
    mov rax, MEMORY_SLOT_SIZE
    sub rax, MEMORY_KEY_SIZE
    cmp r15, rax
    ja @@data_too_large
    
    ; Check if key already exists
    mov rcx, r12
    mov rdx, r13
    call FindSlot
    cmp eax, -1
    jne @@update_existing
    
    ; Find free slot
    call FindFreeSlot
    mov ebx, eax            ; EBX = slot index
    
@@store:
    ; Mark slot as used
    mov byte ptr [slot_used + rbx], 1
    
    ; Update timestamp
    inc qword ptr [current_timestamp]
    mov rax, [current_timestamp]
    mov [slot_timestamp + rbx * 8], rax
    
    ; Compute slot address
    mov rax, rbx
    imul rax, MEMORY_SLOT_SIZE
    lea rdi, [memory_arena + rax]
    
    ; Clear slot
    mov rcx, rdi
    mov rdx, MEMORY_SLOT_SIZE
    call RtlZeroMemory
    
    ; Store key (up to MEMORY_KEY_SIZE)
    mov rcx, rdi
    mov rdx, r12
    mov r8, r13
    cmp r8, MEMORY_KEY_SIZE
    jbe @@key_copy_ok
    mov r8, MEMORY_KEY_SIZE
@@key_copy_ok:
    call RtlCopyMemory
    
    ; Store data (after key)
    lea rcx, [rdi + MEMORY_KEY_SIZE]
    mov rdx, r14
    mov r8, r15
    call RtlCopyMemory
    
    ; Update statistics
    inc qword ptr [mem_store_count]
    
    mov rax, MEM_STATUS_SUCCESS
    jmp @@done
    
@@update_existing:
    mov ebx, eax            ; EBX = existing slot
    jmp @@store
    
@@invalid_key:
    mov rax, MEM_STATUS_INVALID_KEY
    jmp @@done
    
@@invalid_data:
    mov rax, MEM_STATUS_INVALID_DATA
    jmp @@done
    
@@data_too_large:
    mov rax, MEM_STATUS_INVALID_DATA
    jmp @@done
    
@@done:
    add rsp, 56
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
Memory_Store endp

; ============================================================================
; Memory Recall
; int Memory_Recall(const void* key, size_t key_len, void* buffer, size_t buffer_size, size_t* out_len)
; RCX = key, RDX = key_len, R8 = buffer, R9 = buffer_size, [RSP+40] = out_len
; Returns: RAX = status code
; ============================================================================;
Memory_Recall proc
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 72
    
    ; Save arguments
    mov r12, rcx            ; R12 = key
    mov r13, rdx            ; R13 = key_len
    mov r14, r8             ; R14 = buffer
    mov r15, r9             ; R15 = buffer_size
    mov rax, [rsp + 72 + 40] ; RAX = out_len pointer
    mov [rsp + 64], rax     ; Save on stack
    
    ; Validate inputs
    test r12, r12
    jz @@invalid_key
    test r13, r13
    jz @@invalid_key
    test r14, r14
    jz @@invalid_buffer
    test r15, r15
    jz @@buffer_too_small
    
    ; Find slot
    mov rcx, r12
    mov rdx, r13
    call FindSlot
    cmp eax, -1
    je @@not_found
    
    mov ebx, eax            ; EBX = slot index
    
    ; Update timestamp (mark as recently used)
    inc qword ptr [current_timestamp]
    mov rax, [current_timestamp]
    mov [slot_timestamp + rbx * 8], rax
    
    ; Compute slot address
    mov rax, rbx
    imul rax, MEMORY_SLOT_SIZE
    lea rsi, [memory_arena + rax]
    
    ; Calculate data size (slot size - key size)
    mov rcx, MEMORY_SLOT_SIZE
    sub rcx, MEMORY_KEY_SIZE
    
    ; Check if buffer is large enough
    cmp r15, rcx
    jb @@buffer_too_small
    
    ; Copy data to buffer
    lea rcx, [rsi + MEMORY_KEY_SIZE]
    mov rdx, r14
    mov r8, rcx             ; R8 = data size (already computed)
    call RtlCopyMemory
    
    ; Update statistics
    inc qword ptr [mem_recall_count]
    
    ; Return actual data length if requested
    mov rax, [rsp + 64]     ; RAX = out_len pointer
    test rax, rax
    jz @@success
    mov rcx, MEMORY_SLOT_SIZE
    sub rcx, MEMORY_KEY_SIZE
    mov [rax], rcx
    
@@success:
    mov rax, MEM_STATUS_SUCCESS
    jmp @@done
    
@@invalid_key:
    mov rax, MEM_STATUS_INVALID_KEY
    jmp @@done
    
@@invalid_buffer:
    mov rax, MEM_STATUS_INVALID_DATA
    jmp @@done
    
@@buffer_too_small:
    mov rax, MEM_STATUS_INVALID_DATA
    jmp @@done
    
@@not_found:
    mov rax, MEM_STATUS_NOT_FOUND
    jmp @@done
    
@@done:
    add rsp, 72
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
Memory_Recall endp

; ============================================================================
; Memory Clear
; void Memory_Clear(void)
; Clears all memory slots
; ============================================================================;
Memory_Clear proc
    push rbx
    sub rsp, 40
    
    ; Clear arena
    mov rcx, offset memory_arena
    mov rdx, MEMORY_TOTAL_SIZE
    call RtlZeroMemory
    
    ; Clear metadata
    mov rcx, offset slot_used
    mov rdx, MEMORY_SLOT_COUNT
    call RtlZeroMemory
    
    mov rcx, offset slot_timestamp
    mov rdx, MEMORY_SLOT_COUNT * 8
    call RtlZeroMemory
    
    ; Reset counters
    mov qword ptr [current_timestamp], 0
    mov qword ptr [mem_store_count], 0
    mov qword ptr [mem_recall_count], 0
    mov qword ptr [mem_eviction_count], 0
    
    add rsp, 40
    pop rbx
    ret
Memory_Clear endp

; ============================================================================
; Memory Stats
; void Memory_Stats(uint64_t* store_count, uint64_t* recall_count, uint64_t* eviction_count)
; RCX = store_count, RDX = recall_count, R8 = eviction_count
; ============================================================================;
Memory_Stats proc
    test rcx, rcx
    jz @@skip_store
    mov rax, [mem_store_count]
    mov [rcx], rax
@@skip_store:
    
    test rdx, rdx
    jz @@skip_recall
    mov rax, [mem_recall_count]
    mov [rdx], rax
@@skip_recall:
    
    test r8, r8
    jz @@skip_eviction
    mov rax, [mem_eviction_count]
    mov [r8], rax
@@skip_eviction:
    
    ret
Memory_Stats endp

; ============================================================================
; Export Table
; ============================================================================;

public Memory_Store
public Memory_Recall
public Memory_Clear
public Memory_Stats

end
