; ==================================================================================
; SOVEREIGN STREAM SAFE ITERATOR
; File: Sovereign_Stream_Safe_Iterator.asm
; Role: Deterministic GGUF Layout Parsing and KV Skips
; ==================================================================================

include Sovereign_Common.inc
include Sovereign_FrameABI.inc
include Sovereign_GGUF_Schema_Runtime.inc

.CODE

; ==================================================================================
; Sovereign_Skip_ValueData
; Advances RSI past a value of type EAX
; Modifies: RAX, RCX, RDX, RSI
; ==================================================================================
Sovereign_Skip_ValueData PROC
@@CheckScalar:
    cmp eax, GGUF_TYPE_UINT8
    je @@Skip1
    cmp eax, GGUF_TYPE_INT8
    je @@Skip1
    cmp eax, GGUF_TYPE_BOOL
    je @@Skip1
    cmp eax, GGUF_TYPE_UINT16
    je @@Skip2
    cmp eax, GGUF_TYPE_INT16
    je @@Skip2
    cmp eax, GGUF_TYPE_UINT32
    je @@Skip4
    cmp eax, GGUF_TYPE_INT32
    je @@Skip4
    cmp eax, GGUF_TYPE_FLOAT32
    je @@Skip4
    cmp eax, GGUF_TYPE_UINT64
    je @@Skip8
    cmp eax, GGUF_TYPE_INT64
    je @@Skip8
    cmp eax, GGUF_TYPE_FLOAT64
    je @@Skip8
    cmp eax, GGUF_TYPE_STRING
    je @@SkipString
    cmp eax, GGUF_TYPE_ARRAY
    je @@SkipArray
    
    ; Unrecognized type logic (Fail-safe forward to exit or halt)
    ret

@@Skip1:
    add rsi, 1
    ret
@@Skip2:
    add rsi, 2
    ret
@@Skip4:
    add rsi, 4
    ret
@@Skip8:
    add rsi, 8
    ret
@@SkipString:
    mov rcx, [rsi]          ; Read string length
    add rsi, 8              ; Skip QWORD length field
    add rsi, rcx            ; Skip string chars
    ret
@@SkipArray:
    mov edx, [rsi]          ; Read Array Value Type (DWORD)
    add rsi, 4
    mov rcx, [rsi]          ; Read Array Length (QWORD)
    add rsi, 8

@@ArrayLoop:
    test rcx, rcx
    jz @@ArrayDone
    push rcx
    push rdx
    mov eax, edx
    call Sovereign_Skip_ValueData   ; Safe inner advance
    pop rdx
    pop rcx
    dec rcx
    jmp @@ArrayLoop
    
@@ArrayDone:
    ret
Sovereign_Skip_ValueData ENDP

; ==================================================================================
; Sovereign_Skip_KV_Pairs
; Skips exactly RDI key-value pairs safely.
; RSI = Start of KV data
; RDI = Number of pairs
; Returns RSI pointing to start of Tensors
; ==================================================================================
PUBLIC Sovereign_Skip_KV_Pairs
Sovereign_Skip_KV_Pairs PROC
@@KVLoop:
    test rdi, rdi
    jz @@KVDone
    
    ; Skip Key (String)
    mov rax, [rsi]          ; Length of key
    add rsi, 8              ; Skip length field
    add rsi, rax            ; Skip key characters
    
    ; Read Value Type
    mov eax, [rsi]          ; DWORD type
    add rsi, 4              ; Skip type field
    
    ; Skip Value Data
    call Sovereign_Skip_ValueData
    
    dec rdi
    jmp @@KVLoop
    
@@KVDone:
    ret
Sovereign_Skip_KV_Pairs ENDP

END
