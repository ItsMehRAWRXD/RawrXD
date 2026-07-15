; =============================================================================
; SwarmV29_Persistent_Buffer.asm - Zero-Copy GPU Memory
; =============================================================================
; glBufferStorage + persistent mapping for AZDO
; Non-temporal writes, coherent memory access
; Date: 2026-07-08
; =============================================================================

INCLUDE SwarmV29_Macros.inc

; =============================================================================
;                            EXPORTS
; =============================================================================
PUBLIC SwarmV29_Create_Persistent_Buffer
PUBLIC SwarmV29_Destroy_Persistent_Buffer
PUBLIC SwarmV29_Map_Persistent_Buffer
PUBLIC SwarmV29_Unmap_Persistent_Buffer
PUBLIC SwarmV29_Write_Persistent_Buffer
PUBLIC SwarmV29_Flush_Persistent_Buffer

; =============================================================================
;                            DATA
; =============================================================================
.data

; Buffer pool (max 16 persistent buffers)
ALIGN 64
BufferPool SWARMV29_PERSISTENT_BUFFER 16 DUP (<>)
BufferCount DWORD 0

; OpenGL function pointers (loaded at runtime)
ALIGN 8
glGenBuffers           QWORD 0
glDeleteBuffers        QWORD 0
glBindBuffer           QWORD 0
glBufferStorage        QWORD 0
glMapBufferRange       QWORD 0
glUnmapBuffer          QWORD 0
glFlushMappedBufferRange QWORD 0

; Flags for glBufferStorage
GL_MAP_READ_BIT              EQU 0x0001
GL_MAP_WRITE_BIT             EQU 0x0002
GL_MAP_PERSISTENT_BIT        EQU 0040h
GL_MAP_COHERENT_BIT          EQU 0080h
GL_CLIENT_STORAGE_BIT        EQU 0200h

; Flags for glMapBufferRange
GL_MAP_FLUSH_EXPLICIT_BIT    EQU 0x0010

; =============================================================================
;                            CODE
; =============================================================================
.code

; =============================================================================
; SwarmV29_Create_Persistent_Buffer
; Create a persistent mapped buffer
;
; RCX = size (bytes)
; RDX = flags (GL_MAP_READ_BIT | GL_MAP_WRITE_BIT | etc.)
; R8  = gl_context (opaque pointer)
;
; Returns: RAX = buffer handle (index into BufferPool), -1 on failure
; =============================================================================
SwarmV29_Create_Persistent_Buffer PROC FRAME
    SWARMV29_ABI_FRAME
    
    ; Validate parameters
    test rcx, rcx
    jz @@invalid_params
    
    ; Check buffer pool capacity
    mov eax, DWORD PTR [BufferCount]
    cmp eax, 16
    jge @@pool_full
    
    ; Find free slot
    xor ebx, ebx
    mov ecx, DWORD PTR [BufferCount]
    
@@find_slot:
    cmp ebx, ecx
    jge @@found_slot
    
    ; Check if slot is free
    mov rax, BufferPool[rbx * SIZEOF SWARMV29_PERSISTENT_BUFFER].SWARMV29_PERSISTENT_BUFFER.Size
    test rax, rax
    jz @@found_slot
    
    inc ebx
    jmp @@find_slot
    
@@found_slot:
    ; Check if we need to expand pool
    cmp ebx, ecx
    jl @@use_existing_slot
    
    ; Expand pool
    inc DWORD PTR [BufferCount]
    
@@use_existing_slot:
    ; Allocate buffer handle
    mov r12, rbx            ; r12 = slot index
    
    ; Call glGenBuffers
    mov rcx, 1              ; n = 1
    lea rdx, BufferPool[r12 * SIZEOF SWARMV29_PERSISTENT_BUFFER].SWARMV29_PERSISTENT_BUFFER.BufferId
    call QWORD PTR [glGenBuffers]
    
    ; Store size
    mov BufferPool[r12 * SIZEOF SWARMV29_PERSISTENT_BUFFER].SWARMV29_PERSISTENT_BUFFER.Size, rcx
    
    ; Store flags
    mov BufferPool[r12 * SIZEOF SWARMV29_PERSISTENT_BUFFER].SWARMV29_PERSISTENT_BUFFER.Flags, rdx
    
    ; Initialize state
    mov BufferPool[r12 * SIZEOF SWARMV29_PERSISTENT_BUFFER].SWARMV29_PERSISTENT_BUFFER.Mapped, 0
    mov BufferPool[r12 * SIZEOF SWARMV29_PERSISTENT_BUFFER].SWARMV29_PERSISTENT_BUFFER.Ptr, 0
    
    ; Return slot index
    mov rax, r12
    jmp @@done
    
@@invalid_params:
@@pool_full:
    mov rax, -1
    
@@done:
    SWARMV29_ABI_EPILOG
SwarmV29_Create_Persistent_Buffer ENDP

; =============================================================================
; SwarmV29_Destroy_Persistent_Buffer
; Destroy a persistent buffer
;
; RCX = buffer handle (index)
;
; Returns: EAX = 0 on success, -1 on failure
; =============================================================================
SwarmV29_Destroy_Persistent_Buffer PROC FRAME
    SWARMV29_ABI_FRAME
    
    ; Validate handle
    cmp ecx, 0
    jl @@invalid_handle
    cmp ecx, 16
    jge @@invalid_handle
    
    mov r12, rcx            ; r12 = slot index
    
    ; Check if buffer exists
    mov rax, BufferPool[r12 * SIZEOF SWARMV29_PERSISTENT_BUFFER].SWARMV29_PERSISTENT_BUFFER.Size
    test rax, rax
    jz @@invalid_handle
    
    ; Unmap if mapped
    mov eax, BufferPool[r12 * SIZEOF SWARMV29_PERSISTENT_BUFFER].SWARMV29_PERSISTENT_BUFFER.Mapped
    test eax, eax
    jz @@not_mapped
    
    ; Call glUnmapBuffer
    mov rcx, BufferPool[r12 * SIZEOF SWARMV29_PERSISTENT_BUFFER].SWARMV29_PERSISTENT_BUFFER.BufferId
    call QWORD PTR [glUnmapBuffer]
    
@@not_mapped:
    ; Call glDeleteBuffers
    mov rcx, 1
    lea rdx, BufferPool[r12 * SIZEOF SWARMV29_PERSISTENT_BUFFER].SWARMV29_PERSISTENT_BUFFER.BufferId
    call QWORD PTR [glDeleteBuffers]
    
    ; Clear slot
    mov BufferPool[r12 * SIZEOF SWARMV29_PERSISTENT_BUFFER].SWARMV29_PERSISTENT_BUFFER.Size, 0
    mov BufferPool[r12 * SIZEOF SWARMV29_PERSISTENT_BUFFER].SWARMV29_PERSISTENT_BUFFER.Flags, 0
    mov BufferPool[r12 * SIZEOF SWARMV29_PERSISTENT_BUFFER].SWARMV29_PERSISTENT_BUFFER.Mapped, 0
    mov BufferPool[r12 * SIZEOF SWARMV29_PERSISTENT_BUFFER].SWARMV29_PERSISTENT_BUFFER.Ptr, 0
    
    xor eax, eax
    jmp @@done
    
@@invalid_handle:
    mov eax, -1
    
@@done:
    SWARMV29_ABI_EPILOG
SwarmV29_Destroy_Persistent_Buffer ENDP

; =============================================================================
; SwarmV29_Map_Persistent_Buffer
; Map buffer for persistent access
;
; RCX = buffer handle
;
; Returns: RAX = pointer to mapped memory, 0 on failure
; =============================================================================
SwarmV29_Map_Persistent_Buffer PROC FRAME
    SWARMV29_ABI_FRAME
    
    ; Validate handle
    cmp ecx, 0
    jl @@invalid_handle
    cmp ecx, 16
    jge @@invalid_handle
    
    mov r12, rcx
    
    ; Check if already mapped
    mov eax, BufferPool[r12 * SIZEOF SWARMV29_PERSISTENT_BUFFER].SWARMV29_PERSISTENT_BUFFER.Mapped
    test eax, eax
    jnz @@already_mapped
    
    ; Bind buffer
    mov ecx, 0x90EE        ; GL_ARRAY_BUFFER
    mov edx, BufferPool[r12 * SIZEOF SWARMV29_PERSISTENT_BUFFER].SWARMV29_PERSISTENT_BUFFER.BufferId
    call QWORD PTR [glBindBuffer]
    
    ; Map buffer with persistent flags
    mov rcx, 0x90EE         ; GL_ARRAY_BUFFER
    xor rdx, rdx            ; offset = 0
    mov r8, BufferPool[r12 * SIZEOF SWARMV29_PERSISTENT_BUFFER].SWARMV29_PERSISTENT_BUFFER.Size
    mov r9, GL_MAP_WRITE_BIT OR GL_MAP_PERSISTENT_BIT OR GL_MAP_COHERENT_BIT OR GL_MAP_FLUSH_EXPLICIT_BIT
    call QWORD PTR [glMapBufferRange]
    
    ; Store pointer
    mov BufferPool[r12 * SIZEOF SWARMV29_PERSISTENT_BUFFER].SWARMV29_PERSISTENT_BUFFER.Ptr, rax
    mov BufferPool[r12 * SIZEOF SWARMV29_PERSISTENT_BUFFER].SWARMV29_PERSISTENT_BUFFER.Mapped, 1
    
    jmp @@done
    
@@invalid_handle:
@@already_mapped:
    xor rax, rax
    
@@done:
    SWARMV29_ABI_EPILOG
SwarmV29_Map_Persistent_Buffer ENDP

; =============================================================================
; SwarmV29_Unmap_Persistent_Buffer
; Unmap buffer
;
; RCX = buffer handle
;
; Returns: EAX = 0 on success
; =============================================================================
SwarmV29_Unmap_Persistent_Buffer PROC FRAME
    SWARMV29_ABI_FRAME
    
    ; Validate handle
    cmp ecx, 0
    jl @@invalid_handle
    cmp ecx, 16
    jge @@invalid_handle
    
    mov r12, rcx
    
    ; Check if mapped
    mov eax, BufferPool[r12 * SIZEOF SWARMV29_PERSISTENT_BUFFER].SWARMV29_PERSISTENT_BUFFER.Mapped
    test eax, eax
    jz @@not_mapped
    
    ; Unmap
    mov rcx, BufferPool[r12 * SIZEOF SWARMV29_PERSISTENT_BUFFER].SWARMV29_PERSISTENT_BUFFER.BufferId
    call QWORD PTR [glUnmapBuffer]
    
    ; Clear state
    mov BufferPool[r12 * SIZEOF SWARMV29_PERSISTENT_BUFFER].SWARMV29_PERSISTENT_BUFFER.Mapped, 0
    mov BufferPool[r12 * SIZEOF SWARMV29_PERSISTENT_BUFFER].SWARMV29_PERSISTENT_BUFFER.Ptr, 0
    
    xor eax, eax
    jmp @@done
    
@@invalid_handle:
@@not_mapped:
    mov eax, -1
    
@@done:
    SWARMV29_ABI_EPILOG
SwarmV29_Unmap_Persistent_Buffer ENDP

; =============================================================================
; SwarmV29_Write_Persistent_Buffer
; Write data to persistent buffer (non-temporal)
;
; RCX = buffer handle
; RDX = source pointer
; R8  = offset
; R9  = size
;
; Returns: EAX = 0 on success
; =============================================================================
SwarmV29_Write_Persistent_Buffer PROC FRAME
    SWARMV29_ABI_FRAME
    
    ; Validate handle
    cmp ecx, 0
    jl @@invalid_handle
    cmp ecx, 16
    jge @@invalid_handle
    
    mov r12, rcx            ; buffer handle
    mov r13, rdx            ; source
    mov r14, r8             ; offset
    mov r15, r9             ; size
    
    ; Check if mapped
    mov eax, BufferPool[r12 * SIZEOF SWARMV29_PERSISTENT_BUFFER].SWARMV29_PERSISTENT_BUFFER.Mapped
    test eax, eax
    jz @@not_mapped
    
    ; Get buffer pointer
    mov rax, BufferPool[r12 * SIZEOF SWARMV29_PERSISTENT_BUFFER].SWARMV29_PERSISTENT_BUFFER.Ptr
    add rax, r14            ; dest = ptr + offset
    
    ; Non-temporal copy (movntdq)
    mov rsi, r13            ; source
    mov rdi, rax            ; dest
    mov rcx, r15            ; size
    
    ; Check alignment (16-byte for movntdq)
    test rdi, 0Fh
    jnz @@byte_copy
    
    ; Check size alignment
    test rcx, 0Fh
    jnz @@byte_copy
    
    ; Vector copy (16 bytes at a time)
    shr rcx, 4              ; count / 16
    
@@vector_loop:
    test rcx, rcx
    jz @@done_copy
    
    vmovdqu xmm0, xmmword ptr [rsi]
    vmovntdq xmmword ptr [rdi], xmm0
    
    add rsi, 16
    add rdi, 16
    dec rcx
    jmp @@vector_loop
    
@@byte_copy:
    ; Fallback to byte copy
    rep movsb
    
@@done_copy:
    ; Memory fence
    sfence
    
    xor eax, eax
    jmp @@done
    
@@invalid_handle:
@@not_mapped:
    mov eax, -1
    
@@done:
    SWARMV29_ABI_EPILOG
SwarmV29_Write_Persistent_Buffer ENDP

; =============================================================================
; SwarmV29_Flush_Persistent_Buffer
; Flush buffer range
;
; RCX = buffer handle
; RDX = offset
; R8  = size
;
; Returns: EAX = 0 on success
; =============================================================================
SwarmV29_Flush_Persistent_Buffer PROC FRAME
    SWARMV29_ABI_FRAME
    
    ; Validate handle
    cmp ecx, 0
    jl @@invalid_handle
    cmp ecx, 16
    jge @@invalid_handle
    
    mov r12, rcx
    
    ; Check if mapped
    mov eax, BufferPool[r12 * SIZEOF SWARMV29_PERSISTENT_BUFFER].SWARMV29_PERSISTENT_BUFFER.Mapped
    test eax, eax
    jz @@not_mapped
    
    ; Bind buffer
    mov ecx, 0x90EE        ; GL_ARRAY_BUFFER
    mov edx, BufferPool[r12 * SIZEOF SWARMV29_PERSISTENT_BUFFER].SWARMV29_PERSISTENT_BUFFER.BufferId
    call QWORD PTR [glBindBuffer]
    
    ; Flush range
    mov rcx, rdx            ; offset
    mov rdx, r8             ; size
    call QWORD PTR [glFlushMappedBufferRange]
    
    xor eax, eax
    jmp @@done
    
@@invalid_handle:
@@not_mapped:
    mov eax, -1
    
@@done:
    SWARMV29_ABI_EPILOG
SwarmV29_Flush_Persistent_Buffer ENDP

END