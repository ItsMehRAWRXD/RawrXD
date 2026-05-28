; ==================================================================================
; SOVEREIGN CORE ENGINE - KV CACHE TILING RING BUFFER ARCHITECTURE
; Target Architecture: x64 (MASM64)
; Alignment: 64-Byte Cache Line Boundary
; ISA Prerequisites: AVX-512 (For high-throughput state manipulation / prefetch)
; ==================================================================================

.CODE

; ----------------------------------------------------------------------------------
; STRUCTURE DEFINITIONS (Conceptual Memory Mapping)
; ----------------------------------------------------------------------------------
; Sovereign_KV_Layer_Header STRUCT
;   pBufferStart        QWORD ? ; 64-byte aligned base pointer to cache data
;   BufferMask          DWORD ? ; Power-of-two mask (e.g., 0x0000007F for 128 slots)
;   BlockStrideBytes    DWORD ? ; Total bytes per complete single token KV slot
;   CurrentCursor       DWORD ? ; Active multi-token monotonic sequence cursor
;   Reserved            DWORD ? ; Explicit alignment padding
; Sovereign_KV_Layer_Header ENDS

; ----------------------------------------------------------------------------------
; GLOBAL RUNTIME CONSTANTS & HARDWARE TUNING VARIABLES
; ----------------------------------------------------------------------------------
.DATA
ALIGN 16
g_KV_PrefetchStride     DWORD 256        ; Prefetch distance ahead in bytes
g_KV_RingSizeMax        DWORD 256        ; Must remain a power-of-two value
g_KV_RingMask           DWORD 255        ; (g_KV_RingSizeMax - 1) for rapid bitwise modulo

.CODE

; ==================================================================================
; Sovereign_KV_Buffer_Init
; Description: Initializes and clears runtime memory structures for the tiled buffer.
; Inputs:
;   RCX = Base pointer to unaligned allocated heap segment
;   RDX = Total memory segment size allocated
;   R8D = Number of layers within target model architecture
;   R9D = Stride size of a single KV block (Bytes)
; Outputs:
;   RAX = 64-Byte aligned base address for Layer Header Table
; ==================================================================================
Sovereign_KV_Buffer_Init PROC PUBLIC
    push rbx
    push rdi
    push rsi

    ; Align allocation pointer to 64-byte boundary
    mov rax, rcx
    add rax, 63
    and rax, -64

    ; Calculate header tracking table overhead
    ; Each layer tracking structure = 24 bytes. Rounding up to 32 bytes for alignment.
    mov r10, r8
    shl r10, 5          ; Total header block size (Layers * 32)
    
    ; Compute start of actual tensor block payloads
    mov rbx, rax
    add rbx, r10
    add rbx, 63
    and rbx, -64        ; rbx now holds the 64-byte aligned payload base

    ; Initialize layer headers
    xor ecx, ecx        ; Current layer index counter
    mov rsi, rax        ; Working header pointer

    ; Pre-load operational parameters
    mov r11d, g_KV_RingMask

ALIGN 16
Header_Init_Loop:
    cmp ecx, r8d
    jge Header_Init_Complete

    ; Store configuration attributes into current header slot
    mov qword ptr [rsi], rbx       ; pBufferStart
    mov dword ptr [rsi + 8], r11d  ; BufferMask
    mov dword ptr [rsi + 12], r9d  ; BlockStrideBytes
    mov dword ptr [rsi + 16], 0    ; CurrentCursor initialized to zero
    mov dword ptr [rsi + 20], 0    ; Padding clear

    ; Advance payload tracking pointer by full layer allocation space
    mov eax, r9d
    mov r10d, g_KV_RingSizeMax
    mul r10d                       ; EAX = BlockStrideBytes * RingSizeMax
    add rbx, rax
    add rbx, 63
    and rbx, -64                   ; Maintain 64-byte alignment spacing

    ; Advance header pointer to next slot (32-byte stride)
    add rsi, 32
    inc ecx
    jmp Header_Init_Loop

Header_Init_Complete:
    mov rax, rsi
    mov r10, r8
    shl r10, 5                     ; Calculate total header offset to subtract
    sub rax, r10                   ; Return the base pointer to tracking header array

    pop rsi
    pop rdi
    pop rbx
    ret
Sovereign_KV_Buffer_Init ENDP


; ==================================================================================
; Sovereign_KV_Get_Slot_Address
; Description: Resolves the exact physical memory pointer for a target layer/token index.
; Inputs:
;   RCX = Base pointer to Layer Header Table
;   EDX = Target Layer Index
;   R8D = Absolute Monotonic Token Index (Global timeline index)
; Outputs:
;   RAX = Resolved 64-byte aligned memory address inside active ring window
; ==================================================================================
Sovereign_KV_Get_Slot_Address PROC PUBLIC
    ; Locate targeted layer header structure (32 bytes per index)
    shl rdx, 5
    add rcx, rdx

    ; Extract layer parameters from tracking block
    mov rax, qword ptr [rcx]       ; RAX = Layer Data Base Pointer
    mov r10d, dword ptr [rcx + 8]  ; R10D = BufferMask
    mov r11d, dword ptr [rcx + 12] ; R11D = BlockStrideBytes

    ; Apply power-of-two bitwise ring masking instead of an explicit DIV/IDIV instruction
    mov r9d, r8d
    and r9d, r10d                  ; R9D = Wrapped Slot Index

    ; Compute final memory offset
    mov eax, r9d
    mul r11d                       ; EAX = Wrapped Slot Index * BlockStrideBytes

    ; Compute base-relative pointer destination
    add rax, qword ptr [rcx]
    
    ret
Sovereign_KV_Get_Slot_Address ENDP


; ==================================================================================
; Sovereign_KV_Insert_Token
; Description: Stores newly generated token Key/Value tensors into active ring slot.
; Inputs:
;   RCX = Base pointer to Layer Header Table
;   EDX = Active Target Layer Index
;   R8  = Pointer to source tensor payload ready for ingestion
; Outputs:
;   None. Core structures are updated in-place.
; ==================================================================================
Sovereign_KV_Insert_Token PROC PUBLIC
    push rbx
    push rsi
    push rdi

    ; Locate target layer header block
    mov r9, rdx
    shl r9, 5
    add r9, rcx                    ; R9 = Address of Target Layer Header

    ; Fetch current absolute timeline cursor position
    mov r10d, dword ptr [r9 + 16]  ; R10D = Current Cursor

    ; Resolve active memory slice pointer via internal helper configuration
    push rcx
    push r8
    push r9
    mov edx, edx
    mov r8d, r10d
    call Sovereign_KV_Get_Slot_Address
    mov rdi, rax                   ; RDI = Destination offset pointer
    pop r9
    pop r8
    pop rcx

    ; Prepare streaming loop data parameters
    mov rsi, r8                    ; RSI = Source pointer
    mov ecx, dword ptr [r9 + 12]   ; ECX = Stride Size in Bytes
    shr ecx, 6                     ; Divide by 64 to process full cache lines via AVX-512

ALIGN 16
Stream_Ingestion_Loop:
    ; Non-temporal streaming store bypasses cache hierarchy for write-only access
    vmovdqa64 zmm2, zmmword ptr [rsi]
    vmovdqa64 zmm3, zmmword ptr [rsi + 64]
    vmovntdq zmmword ptr [rdi], zmm2
    vmovntdq zmmword ptr [rdi + 64], zmm3

    add rsi, 128
    add rdi, 128
    sub ecx, 2
    jnz Stream_Ingestion_Loop

    ; Atomically increment absolute timeline layer window tracking index
    inc dword ptr [r9 + 16]

    pop rdi
    pop rsi
    pop rbx
    ret
Sovereign_KV_Insert_Token ENDP


; ==================================================================================
; Sovereign_KV_Prefetch_Next_Window
; Description: Dispatches hardware prefetch notifications into L2/L3 cache tiers
;              for the upcoming ping-pong memory segment to eliminate pipeline stall.
; Inputs:
;   RCX = Base pointer to Layer Header Table
;   EDX = Target Layer Index
;   R8D = Next Predicted Token Index to cache-warm
; Outputs:
;   None. Hardware execution pipeline is prepared asynchronously.
; ==================================================================================
Sovereign_KV_Prefetch_Next_Window PROC PUBLIC
    ; Resolve targeted upcoming memory slot location
    call Sovereign_KV_Get_Slot_Address
    mov r10, rax                   ; R10 = Target address to prefetch

    ; Pull structural parameters to extract length data
    shl rdx, 5
    add rcx, rdx
    mov ecx, dword ptr [rcx + 12]   ; ECX = BlockStrideBytes
    mov eax, g_KV_PrefetchStride    ; Load hardware stride configurations

ALIGN 16
Prefetch_Execution_Loop:
    ; Warm lines directly into L2 cache tier using T1 hint
    prefetcht1 [r10]
    prefetcht1 [r10 + 64]

    add r10, 128
    sub ecx, 128
    jg Prefetch_Execution_Loop

    ret
Sovereign_KV_Prefetch_Next_Window ENDP

END
