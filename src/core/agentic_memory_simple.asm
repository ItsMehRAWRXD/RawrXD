; ============================================================================
; agentic_memory_simple.asm — RawrXD Simple Index-Based Memory Layer
; ============================================================================
;
; Simplified memory layer using direct index-based access.
; No hash tables, no complex pointer arithmetic - just simple indexing.
;
; Build: ml64.exe /c agentic_memory_simple.asm
; Link:  link.exe agentic_memory_simple.obj [other objs] /OUT:AgenticUnified.exe
;
; ============================================================================

; ============================================================================
; External Imports
; ============================================================================

extern RtlZeroMemory:proc
extern RtlCopyMemory:proc

; ============================================================================
; Constants
; ============================================================================

; Memory configuration
MEM_MAX_SLOTS           equ 256         ; 256 slots (0-255)
MEM_SLOT_SIZE           equ 1024        ; 1KB per slot
MEM_TOTAL_SIZE          equ MEM_MAX_SLOTS * MEM_SLOT_SIZE

; Status codes
MEM_OK                  equ 0
MEM_INVALID_INDEX       equ 1
MEM_INVALID_POINTER     equ 2
MEM_SLOT_EMPTY          equ 3

; ============================================================================
; Data Section
; ============================================================================

.data

; Memory arena - 256KB total (256 slots × 1KB)
ALIGN 16
mem_arena:
    db MEM_TOTAL_SIZE dup(0)

; Slot occupancy bitmap (1 = used, 0 = empty)
ALIGN 16
mem_slot_used:
    db MEM_MAX_SLOTS dup(0)

; ============================================================================
; Code Section
; ============================================================================

.code

; ============================================================================
; Calculate Slot Address
; Internal helper - computes address of slot N
; RCX = slot index
; Returns: RAX = address of slot
; ============================================================================
SlotAddress proc
    ; Bounds check already done by caller
    ; Address = mem_arena + (index * MEM_SLOT_SIZE)
    mov rax, rcx
    imul rax, MEM_SLOT_SIZE
    lea rax, [mem_arena + rax]
    ret
SlotAddress endp

; ============================================================================
; Memory Save (Index-Based)
; int Mem_Save(uint64_t index, void* data, uint64_t size)
; RCX = slot index (0-255), RDX = data pointer, R8 = data size
; Returns: RAX = status code
; ============================================================================
Mem_Save proc
    push rbx
    push rdi
    push rsi
    sub rsp, 40
    
    mov rbx, rcx            ; RBX = index
    mov rsi, rdx            ; RSI = data pointer
    mov rdi, r8             ; RDI = size
    
    ; Validate index
    cmp rbx, MEM_MAX_SLOTS
    jae @@invalid_index
    
    ; Validate pointer
    test rsi, rsi
    jz @@invalid_pointer
    
    ; Validate size (must fit in slot)
    test rdi, rdi
    jz @@invalid_pointer
    cmp rdi, MEM_SLOT_SIZE
    ja @@invalid_pointer
    
    ; Mark slot as used
    mov byte ptr [mem_slot_used + rbx], 1
    
    ; Get slot address
    mov rcx, rbx
    call SlotAddress
    mov rdi, rax            ; RDI = slot address
    
    ; Clear slot first
    mov rcx, rdi
    mov rdx, MEM_SLOT_SIZE
    call RtlZeroMemory
    
    ; Copy data to slot
    mov rcx, rdi            ; Destination
    mov rdx, rsi            ; Source
    mov r8, r8              ; Size (already in R8)
    call RtlCopyMemory
    
    mov rax, MEM_OK
    jmp @@done
    
@@invalid_index:
    mov rax, MEM_INVALID_INDEX
    jmp @@done
    
@@invalid_pointer:
    mov rax, MEM_INVALID_POINTER
    
@@done:
    add rsp, 40
    pop rsi
    pop rdi
    pop rbx
    ret
Mem_Save endp

; ============================================================================
; Memory Recall (Index-Based)
; int Mem_Recall(uint64_t index, void* buffer, uint64_t buffer_size)
; RCX = slot index (0-255), RDX = buffer pointer, R8 = buffer size
; Returns: RAX = status code
; ============================================================================
Mem_Recall proc
    push rbx
    push rdi
    push rsi
    sub rsp, 40
    
    mov rbx, rcx            ; RBX = index
    mov rdi, rdx            ; RDI = buffer pointer
    mov rsi, r8             ; RSI = buffer size
    
    ; Validate index
    cmp rbx, MEM_MAX_SLOTS
    jae @@invalid_index
    
    ; Validate buffer
    test rdi, rdi
    jz @@invalid_pointer
    test rsi, rsi
    jz @@invalid_pointer
    
    ; Check if slot is used
    movzx eax, byte ptr [mem_slot_used + rbx]
    test eax, eax
    jz @@slot_empty
    
    ; Get slot address
    mov rcx, rbx
    call SlotAddress
    mov rbx, rax            ; RBX = slot address
    
    ; Calculate copy size (min of slot size and buffer size)
    mov r8, MEM_SLOT_SIZE
    cmp rsi, r8
    cmovb r8, rsi           ; R8 = min(buffer_size, MEM_SLOT_SIZE)
    
    ; Copy data from slot to buffer
    mov rcx, rdi            ; Destination (buffer)
    mov rdx, rbx            ; Source (slot)
    ; R8 already set
    call RtlCopyMemory
    
    mov rax, MEM_OK
    jmp @@done
    
@@invalid_index:
    mov rax, MEM_INVALID_INDEX
    jmp @@done
    
@@invalid_pointer:
    mov rax, MEM_INVALID_POINTER
    jmp @@done
    
@@slot_empty:
    mov rax, MEM_SLOT_EMPTY
    
@@done:
    add rsp, 40
    pop rsi
    pop rdi
    pop rbx
    ret
Mem_Recall endp

; ============================================================================
; Memory Clear Slot
; void Mem_ClearSlot(uint64_t index)
; RCX = slot index (0-255)
; ============================================================================
Mem_ClearSlot proc
    push rbx
    sub rsp, 40
    
    mov rbx, rcx
    
    ; Validate index
    cmp rbx, MEM_MAX_SLOTS
    jae @@done
    
    ; Mark as unused
    mov byte ptr [mem_slot_used + rbx], 0
    
    ; Clear the slot
    mov rcx, rbx
    call SlotAddress
    mov rcx, rax
    mov rdx, MEM_SLOT_SIZE
    call RtlZeroMemory
    
@@done:
    add rsp, 40
    pop rbx
    ret
Mem_ClearSlot endp

; ============================================================================
; Memory Clear All
; void Mem_ClearAll(void)
; Clears entire memory arena
; ============================================================================
Mem_ClearAll proc
    push rbx
    sub rsp, 40
    
    ; Clear arena
    lea rcx, [mem_arena]
    mov rdx, MEM_TOTAL_SIZE
    call RtlZeroMemory
    
    ; Clear occupancy bitmap
    lea rcx, [mem_slot_used]
    mov rdx, MEM_MAX_SLOTS
    call RtlZeroMemory
    
    add rsp, 40
    pop rbx
    ret
Mem_ClearAll endp

; ============================================================================
; Export Table
; ============================================================================

public Mem_Save
public Mem_Recall
public Mem_ClearSlot
public Mem_ClearAll

end
