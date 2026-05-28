; ==============================================================================
; SwarmV29_Persistent_Buffer.asm
; PHASE-29f: Persistent GPU Buffer Management (AZDO Architecture)
; Target: Zero-copy data transfer for AVX-512 PQC pipeline
; ------------------------------------------------------------------------------
; Architecture:
;   - Uses glBufferStorage for immutable storage (GL 4.4+)
;   - Persistent mapping eliminates driver copy overhead
;   - Direct write access from SwarmV29 kernels to GPU memory
;   - Synchronization via fences for coherent access
;
; ABI: Windows x64 (RCX, RDX, R8, R9)
; Dependencies: SwarmV29_Macros.inc
; ==============================================================================

INCLUDE SwarmV29_Macros.inc

; ==============================================================================
; External OpenGL Function Pointers
; ==============================================================================
EXTERN p_glGenBuffers : QWORD
EXTERN p_glDeleteBuffers : QWORD
EXTERN p_glBindBuffer : QWORD
EXTERN p_glBufferStorage : QWORD
EXTERN p_glMapBufferRange : QWORD
EXTERN p_glUnmapBuffer : QWORD
EXTERN p_glFlushMappedBufferRange : QWORD
EXTERN p_glFenceSync : QWORD
EXTERN p_glClientWaitSync : QWORD
EXTERN p_glDeleteSync : QWORD

; ==============================================================================
; OpenGL Constants
; ==============================================================================
GL_ARRAY_BUFFER             EQU 8892h
GL_ELEMENT_ARRAY_BUFFER     EQU 8893h
GL_UNIFORM_BUFFER           EQU 8A11h
GL_SHADER_STORAGE_BUFFER    EQU 90D2h
GL_PIXEL_UNPACK_BUFFER      EQU 88EBh
GL_TRANSFORM_FEEDBACK_BUFFER EQU 8E8Fh

; GL Buffer Storage Flags
GL_MAP_READ_BIT                 EQU 0001h
GL_MAP_WRITE_BIT                EQU 0002h
GL_MAP_PERSISTENT_BIT           EQU 0040h
GL_MAP_COHERENT_BIT             EQU 0080h
GL_MAP_FLUSH_EXPLICIT_BIT       EQU 0010h
GL_MAP_UNSYNCHRONIZED_BIT       EQU 0020h
GL_CLIENT_STORAGE_BIT            EQU 0200h

; GL Sync Constants
GL_SYNC_GPU_COMMANDS_COMPLETE    EQU 9117h
GL_ALREADY_SIGNALED              EQU 911Ah
GL_TIMEOUT_EXPIRED               EQU 911Bh
GL_CONDITION_SATISFIED           EQU 911Ch
GL_WAIT_FAILED                   EQU 911Dh

; ==============================================================================
; Buffer Structure (64-byte cache-aligned)
; ==============================================================================
.data
    ALIGN 64
    SwarmV29_Persistent_Buffer STRUCT
        BufferID            DWORD ?        ; OpenGL buffer handle
        Target              DWORD ?        ; Buffer target (GL_ARRAY_BUFFER, etc.)
        Size                QWORD ?        ; Buffer size in bytes
        MappedPtr           QWORD ?        ; Persistent mapped pointer
        SyncObject          QWORD ?        ; Fence sync object
        Flags               DWORD ?        ; Storage flags
        Alignment           DWORD ?        ; Required alignment (64-byte for AVX-512)
        WriteOffset         QWORD ?        ; Current write offset
        ReadOffset          QWORD ?        ; Current read offset
        Padding            BYTE 24 dup(?)
    SwarmV29_Persistent_Buffer ENDS

    ; Global buffer pool
    ALIGN 64
    g_BufferPool LABEL QWORD
    MAX_BUFFERS EQU 16
    SwarmV29_Persistent_Buffer g_Buffers[MAX_BUFFERS] <>

    ; Buffer pool management
    ALIGN 8
    g_BufferCount      DWORD 0
    g_NextFreeBuffer   DWORD 0
    g_TotalBytesMapped QWORD 0
    g_TotalBytesFlushed QWORD 0

.code

; ==============================================================================
; Persistent_Buffer_Create
; Creates an immutable buffer with persistent mapping
; Input: RCX = Size in bytes, RDX = Target (GL_ARRAY_BUFFER, etc.), R8 = Flags
; Output: RAX = Buffer index, -1 on failure
; ==============================================================================
ALIGN 16
Persistent_Buffer_Create PROC
    SWARM_PROC_START Persistent_Buffer_Create, <rbx, rdi>
    
    ; Validate parameters
    SWARM_CHECK_NULL rcx, .Error_Invalid_Size
    test rcx, rcx
    jle .Error_Invalid_Size
    
    ; Check buffer pool capacity
    mov eax, [g_BufferCount]
    cmp eax, MAX_BUFFERS
    jge .Error_Pool_Full
    
    ; Find free slot
    mov eax, [g_NextFreeBuffer]
    lea rbx, [g_Buffers]
    imul eax, eax, SIZEOF SwarmV29_Persistent_Buffer
    add rbx, rax
    
    ; Generate buffer
    sub rsp, 40
    lea rdi, [rbx + SwarmV29_Persistent_Buffer.BufferID]
    mov rcx, 1
    lea rdx, [rdi]
    cmp qword ptr [p_glGenBuffers], 0
    je .Error_Null_Pointer
    call [p_glGenBuffers]
    add rsp, 40
    
    ; Store buffer properties
    mov dword ptr [rbx + SwarmV29_Persistent_Buffer.Target], edx
    mov qword ptr [rbx + SwarmV29_Persistent_Buffer.Size], rcx
    mov dword ptr [rbx + SwarmV29_Persistent_Buffer.Flags], r8d
    mov dword ptr [rbx + SwarmV29_Persistent_Buffer.Alignment], 64  ; AVX-512 alignment
    
    ; Bind buffer
    mov rcx, edx                        ; Target
    mov edx, dword ptr [rbx + SwarmV29_Persistent_Buffer.BufferID]
    cmp qword ptr [p_glBindBuffer], 0
    je .Error_Null_Pointer
    call [p_glBindBuffer]
    
    ; Create immutable storage with persistent mapping
    ; glBufferStorage(target, size, data, flags)
    mov rcx, dword ptr [rbx + SwarmV29_Persistent_Buffer.Target]
    mov rdx, qword ptr [rbx + SwarmV29_Persistent_Buffer.Size]
    xor r8, r8                          ; NULL initial data
    mov r9d, dword ptr [rbx + SwarmV29_Persistent_Buffer.Flags]
    
    ; Add persistent mapping flags
    or r9d, GL_MAP_WRITE_BIT
    or r9d, GL_MAP_PERSISTENT_BIT
    or r9d, GL_MAP_COHERENT_BIT
    or r9d, GL_CLIENT_STORAGE_BIT
    
    cmp qword ptr [p_glBufferStorage], 0
    je .Error_Null_Pointer
    call [p_glBufferStorage]
    
    ; Map buffer persistently
    ; glMapBufferRange(target, offset, length, access)
    mov rcx, dword ptr [rbx + SwarmV29_Persistent_Buffer.Target]
    xor rdx, rdx                        ; Offset = 0
    mov r8, qword ptr [rbx + SwarmV29_Persistent_Buffer.Size]
    mov r9d, GL_MAP_WRITE_BIT
    or r9d, GL_MAP_PERSISTENT_BIT
    or r9d, GL_MAP_COHERENT_BIT
    
    cmp qword ptr [p_glMapBufferRange], 0
    je .Error_Null_Pointer
    call [p_glMapBufferRange]
    
    ; Store mapped pointer
    mov qword ptr [rbx + SwarmV29_Persistent_Buffer.MappedPtr], rax
    test rax, rax
    jz .Error_Map_Failed
    
    ; Update pool counters
    inc dword ptr [g_BufferCount]
    mov eax, [g_NextFreeBuffer]
    inc eax
    mov [g_NextFreeBuffer], eax
    
    ; Update total bytes mapped
    add qword ptr [g_TotalBytesMapped], rcx
    
    ; Return buffer index
    mov rax, [g_BufferCount]
    dec rax
    jmp .Epilogue
    
.Error_Invalid_Size:
    mov rax, -1
    int 3
    jmp .Epilogue
    
.Error_Pool_Full:
    mov rax, -2
    int 3
    jmp .Epilogue
    
.Error_Null_Pointer:
    mov rax, -3
    int 3
    jmp .Epilogue
    
.Error_Map_Failed:
    mov rax, -4
    int 3
    jmp .Epilogue
    
.Epilogue:
    SWARM_PROC_END
Persistent_Buffer_Create ENDP

; ==============================================================================
; Persistent_Buffer_Write
; Writes data to persistent mapped buffer (zero-copy)
; Input: RCX = Buffer index, RDX = Source pointer, R8 = Size in bytes
; Output: RAX = Bytes written, -1 on failure
; ==============================================================================
ALIGN 16
Persistent_Buffer_Write PROC
    SWARM_PROC_START Persistent_Buffer_Write, <rbx, rdi, rsi>
    
    ; Validate buffer index
    cmp ecx, 0
    jl .Error_Invalid_Index
    mov eax, [g_BufferCount]
    cmp ecx, eax
    jge .Error_Invalid_Index
    
    ; Validate pointers
    SWARM_CHECK_NULL rdx, .Error_Null_Pointer
    test r8, r8
    jle .Error_Invalid_Size
    
    ; Get buffer
    mov eax, ecx
    imul eax, eax, SIZEOF SwarmV29_Persistent_Buffer
    lea rbx, [g_Buffers + rax]
    
    ; Check if mapped
    mov rax, qword ptr [rbx + SwarmV29_Persistent_Buffer.MappedPtr]
    test rax, rax
    jz .Error_Not_Mapped
    
    ; Check size bounds
    mov rdi, qword ptr [rbx + SwarmV29_Persistent_Buffer.Size]
    mov rsi, qword ptr [rbx + SwarmV29_Persistent_Buffer.WriteOffset]
    add rsi, r8
    cmp rsi, rdi
    ja .Error_Buffer_Overflow
    
    ; Calculate destination pointer
    mov rdi, rax                        ; Base pointer
    add rdi, qword ptr [rbx + SwarmV29_Persistent_Buffer.WriteOffset]
    
    ; AVX-512 optimized copy (vmovdqa64)
    ; For now, use simple copy - can be optimized with AVX-512 later
    mov rsi, rdx                        ; Source
    mov rcx, r8                         ; Size
    rep movsb
    
    ; Update write offset
    mov rax, qword ptr [rbx + SwarmV29_Persistent_Buffer.WriteOffset]
    add rax, r8
    mov qword ptr [rbx + SwarmV29_Persistent_Buffer.WriteOffset], rax
    
    ; Return bytes written
    mov rax, r8
    jmp .Epilogue
    
.Error_Invalid_Index:
    mov rax, -1
    int 3
    jmp .Epilogue
    
.Error_Null_Pointer:
    mov rax, -2
    int 3
    jmp .Epilogue
    
.Error_Invalid_Size:
    mov rax, -3
    int 3
    jmp .Epilogue
    
.Error_Not_Mapped:
    mov rax, -4
    int 3
    jmp .Epilogue
    
.Error_Buffer_Overflow:
    mov rax, -5
    int 3
    jmp .Epilogue
    
.Epilogue:
    SWARM_PROC_END
Persistent_Buffer_Write ENDP

; ==============================================================================
; Persistent_Buffer_Write_NonTemporal
; Non-temporal write for large-scale data transfers (bypasses CPU cache)
; Input: RCX = Buffer index, RDX = Source pointer, R8 = Size in bytes
; Output: RAX = Bytes written, -1 on failure
; CRITICAL: Uses vmovntdq to bypass cache. MUST call sfence before
;           InsertFence to ensure write-combining buffers are flushed.
; ==============================================================================
ALIGN 16
Persistent_Buffer_Write_NonTemporal PROC
    SWARM_PROC_START Persistent_Buffer_Write_NonTemporal, <rbx, rdi, rsi>
    
    ; Validate buffer index
    cmp ecx, 0
    jl .Error_Invalid_Index_NT
    mov eax, [g_BufferCount]
    cmp ecx, eax
    jge .Error_Invalid_Index_NT
    
    ; Validate pointers
    SWARM_CHECK_NULL rdx, .Error_Null_Pointer_NT
    test r8, r8
    jle .Error_Invalid_Size_NT
    
    ; Get buffer
    mov eax, ecx
    imul eax, eax, SIZEOF SwarmV29_Persistent_Buffer
    lea rbx, [g_Buffers + rax]
    
    ; Check if mapped
    mov rax, qword ptr [rbx + SwarmV29_Persistent_Buffer.MappedPtr]
    test rax, rax
    jz .Error_Not_Mapped_NT
    
    ; Check size bounds
    mov rdi, qword ptr [rbx + SwarmV29_Persistent_Buffer.Size]
    mov rsi, qword ptr [rbx + SwarmV29_Persistent_Buffer.WriteOffset]
    add rsi, r8
    cmp rsi, rdi
    ja .Error_Buffer_Overflow_NT
    
    ; Calculate destination pointer
    mov rdi, rax                        ; Base pointer
    add rdi, qword ptr [rbx + SwarmV29_Persistent_Buffer.WriteOffset]
    
    ; ========================================================================
    ; NON-TEMPORAL AVX-512 WRITE (Bypasses CPU Cache)
    ; ========================================================================
    ; vmovntdq bypasses L1/L2/L3 caches and writes directly to
    ; write-combining buffers, maximizing PCIe burst throughput.
    ; This prevents cache pollution when pushing large PQC matrices.
    ; ========================================================================
    
    ; Check if size is at least 64 bytes (one ZMM register)
    cmp r8, 64
    jb .Small_Write_NT
    
    ; Align destination to 64-byte boundary
    mov rcx, rdi
    and rcx, 3Fh                        ; Check alignment
    jz .Aligned_Write_NT                 ; Already aligned
    
    ; Calculate bytes to copy before alignment
    neg rcx
    add rcx, 64                         ; Bytes needed to reach 64-byte boundary
    
    ; Copy unaligned prefix with standard mov
    mov rsi, rdx                        ; Source
    mov rax, rcx                        ; Bytes to copy
    sub r8, rcx                         ; Remaining bytes
    rep movsb
    
    ; Now aligned to 64-byte boundary
.Aligned_Write_NT:
    mov rsi, rdx                        ; Source (updated)
    mov rdi, rdi                        ; Destination (updated)
    mov rcx, r8                         ; Remaining bytes
    
    ; Calculate number of 64-byte blocks
    shr rcx, 6                          ; Divide by 64
    test rcx, rcx
    jz .Tail_Write_NT
    
    ; Non-temporal ZMM write loop
    align 16
.Write_Loop_NT:
    vmovdqa64 zmm0, [rsi]               ; Load 64 bytes (cached load)
    vmovntdq [rdi], zmm0                ; Non-temporal store (bypasses cache)
    add rsi, 64
    add rdi, 64
    dec rcx
    jnz .Write_Loop_NT
    
    ; Handle remaining bytes
    and r8, 63                          ; Remaining bytes (0-63)
    
.Tail_Write_NT:
    test r8, r8
    jz .Write_Complete_NT
    
    ; Copy remaining bytes with standard mov
    mov rcx, r8
    rep movsb
    
.Write_Complete_NT:
    ; Update write offset
    mov rax, qword ptr [rbx + SwarmV29_Persistent_Buffer.WriteOffset]
    add rax, r8
    mov qword ptr [rbx + SwarmV29_Persistent_Buffer.WriteOffset], rax
    
    ; Return bytes written
    mov rax, r8
    jmp .Epilogue_NT
    
.Small_Write_NT:
    ; For small writes, use standard copy
    mov rsi, rdx
    mov rcx, r8
    rep movsb
    jmp .Write_Complete_NT
    
.Error_Invalid_Index_NT:
    mov rax, -1
    int 3
    jmp .Epilogue_NT
    
.Error_Null_Pointer_NT:
    mov rax, -2
    int 3
    jmp .Epilogue_NT
    
.Error_Invalid_Size_NT:
    mov rax, -3
    int 3
    jmp .Epilogue_NT
    
.Error_Not_Mapped_NT:
    mov rax, -4
    int 3
    jmp .Epilogue_NT
    
.Error_Buffer_Overflow_NT:
    mov rax, -5
    int 3
    jmp .Epilogue_NT
    
.Epilogue_NT:
    SWARM_PROC_END
Persistent_Buffer_Write_NonTemporal ENDP

; ==============================================================================
; Persistent_Buffer_Flush
; Flushes written range to GPU (explicit flush for non-coherent)
; Input: RCX = Buffer index, RDX = Offset, R8 = Size
; Output: RAX = 0 on success
; ==============================================================================
ALIGN 16
Persistent_Buffer_Flush PROC
    SWARM_PROC_START Persistent_Buffer_Flush, <rbx>
    
    ; Validate buffer index
    cmp ecx, 0
    jl .Error_Invalid_Index
    mov eax, [g_BufferCount]
    cmp ecx, eax
    jge .Error_Invalid_Index
    
    ; Get buffer
    mov eax, ecx
    imul eax, eax, SIZEOF SwarmV29_Persistent_Buffer
    lea rbx, [g_Buffers + rax]
    
    ; Flush range
    ; glFlushMappedBufferRange(target, offset, length)
    mov rcx, dword ptr [rbx + SwarmV29_Persistent_Buffer.Target]
    mov rdx, rdx                        ; Offset
    mov r8, r8                          ; Size
    
    cmp qword ptr [p_glFlushMappedBufferRange], 0
    je .Error_Null_Pointer
    call [p_glFlushMappedBufferRange]
    
    ; Update flushed bytes
    add qword ptr [g_TotalBytesFlushed], r8
    
    xor rax, rax
    jmp .Epilogue
    
.Error_Invalid_Index:
    mov rax, -1
    int 3
    jmp .Epilogue
    
.Error_Null_Pointer:
    mov rax, -2
    int 3
    jmp .Epilogue
    
.Epilogue:
    SWARM_PROC_END
Persistent_Buffer_Flush ENDP

; ==============================================================================
; Persistent_Buffer_InsertFence
; Inserts synchronization fence for GPU completion
; Input: RCX = Buffer index
; Output: RAX = Sync object handle
; CRITICAL: Issues sfence before glFenceSync to ensure all pending
;           vector writes are evicted from CPU store buffers before
;           the OpenGL command stream registers the signaling fence.
; ==============================================================================
ALIGN 16
Persistent_Buffer_InsertFence PROC
    SWARM_PROC_START Persistent_Buffer_InsertFence, <rbx>
    
    ; Validate buffer index
    cmp ecx, 0
    jl .Error_Invalid_Index
    mov eax, [g_BufferCount]
    cmp ecx, eax
    jge .Error_Invalid_Index
    
    ; Get buffer
    mov eax, ecx
    imul eax, eax, SIZEOF SwarmV29_Persistent_Buffer
    lea rbx, [g_Buffers + rax]
    
    ; ========================================================================
    ; STORE SERIALIZATION (Critical for Coherent Mapping)
    ; ========================================================================
    ; Ensure all pending vector writes (vmovdqa64/vmovntdq) are evicted
    ; from CPU store buffers before registering the fence with OpenGL.
    ; Without this, the GPU may see stale data when the fence signals.
    ; ========================================================================
    sfence                              ; Serialize all pending stores
    
    ; Insert fence
    ; glFenceSync(GL_SYNC_GPU_COMMANDS_COMPLETE, 0)
    mov rcx, GL_SYNC_GPU_COMMANDS_COMPLETE
    xor rdx, rdx
    
    cmp qword ptr [p_glFenceSync], 0
    je .Error_Null_Pointer
    call [p_glFenceSync]
    
    ; Store sync object
    mov qword ptr [rbx + SwarmV29_Persistent_Buffer.SyncObject], rax
    
    jmp .Epilogue
    
.Error_Invalid_Index:
    xor rax, rax
    int 3
    jmp .Epilogue
    
.Error_Null_Pointer:
    xor rax, rax
    int 3
    jmp .Epilogue
    
.Epilogue:
    SWARM_PROC_END
Persistent_Buffer_InsertFence ENDP

; ==============================================================================
; Persistent_Buffer_WaitFence
; Waits for GPU to complete operations on buffer
; Input: RCX = Buffer index, RDX = Timeout in nanoseconds
; Output: RAX = 0 on success, non-zero on timeout/error
; ==============================================================================
ALIGN 16
Persistent_Buffer_WaitFence PROC
    SWARM_PROC_START Persistent_Buffer_WaitFence, <rbx>
    
    ; Validate buffer index
    cmp ecx, 0
    jl .Error_Invalid_Index
    mov eax, [g_BufferCount]
    cmp ecx, eax
    jge .Error_Invalid_Index
    
    ; Get buffer
    mov eax, ecx
    imul eax, eax, SIZEOF SwarmV29_Persistent_Buffer
    lea rbx, [g_Buffers + rax]
    
    ; Get sync object
    mov rcx, qword ptr [rbx + SwarmV29_Persistent_Buffer.SyncObject]
    test rcx, rcx
    jz .Error_No_Fence
    
    ; Wait for sync
    ; glClientWaitSync(sync, flags, timeout)
    xor rdx, rdx                        ; Flags = 0
    mov r8, rdx                         ; Timeout (from parameter)
    
    cmp qword ptr [p_glClientWaitSync], 0
    je .Error_Null_Pointer
    call [p_glClientWaitSync]
    
    ; Check result
    cmp eax, GL_ALREADY_SIGNALED
    je .Success
    cmp eax, GL_CONDITION_SATISFIED
    je .Success
    
    ; Timeout or error
    mov rax, 1
    jmp .Epilogue
    
.Success:
    xor rax, rax
    jmp .Epilogue
    
.Error_Invalid_Index:
    mov rax, -1
    int 3
    jmp .Epilogue
    
.Error_No_Fence:
    mov rax, -2
    int 3
    jmp .Epilogue
    
.Error_Null_Pointer:
    mov rax, -3
    int 3
    jmp .Epilogue
    
.Epilogue:
    SWARM_PROC_END
Persistent_Buffer_WaitFence ENDP

; ==============================================================================
; Persistent_Buffer_Destroy
; Destroys a persistent buffer and unmaps it
; Input: RCX = Buffer index
; Output: RAX = 0 on success
; ==============================================================================
ALIGN 16
Persistent_Buffer_Destroy PROC
    SWARM_PROC_START Persistent_Buffer_Destroy, <rbx>
    
    ; Validate buffer index
    cmp ecx, 0
    jl .Error_Invalid_Index
    mov eax, [g_BufferCount]
    cmp ecx, eax
    jge .Error_Invalid_Index
    
    ; Get buffer
    mov eax, ecx
    imul eax, eax, SIZEOF SwarmV29_Persistent_Buffer
    lea rbx, [g_Buffers + rax]
    
    ; Unmap buffer if mapped
    mov rax, qword ptr [rbx + SwarmV29_Persistent_Buffer.MappedPtr]
    test rax, rax
    jz .Skip_Unmap
    
    ; glUnmapBuffer(target)
    mov rcx, dword ptr [rbx + SwarmV29_Persistent_Buffer.Target]
    cmp qword ptr [p_glUnmapBuffer], 0
    je .Error_Null_Pointer
    call [p_glUnmapBuffer]
    
.Skip_Unmap:
    ; Delete sync object if exists
    mov rcx, qword ptr [rbx + SwarmV29_Persistent_Buffer.SyncObject]
    test rcx, rcx
    jz .Skip_Sync_Delete
    cmp qword ptr [p_glDeleteSync], 0
    je .Error_Null_Pointer
    call [p_glDeleteSync]
    
.Skip_Sync_Delete:
    ; Delete buffer
    lea rdi, [rbx + SwarmV29_Persistent_Buffer.BufferID]
    mov rcx, 1
    lea rdx, [rdi]
    cmp qword ptr [p_glDeleteBuffers], 0
    je .Error_Null_Pointer
    call [p_glDeleteBuffers]
    
    ; Clear buffer structure
    mov qword ptr [rbx + SwarmV29_Persistent_Buffer.MappedPtr], 0
    mov qword ptr [rbx + SwarmV29_Persistent_Buffer.SyncObject], 0
    mov dword ptr [rbx + SwarmV29_Persistent_Buffer.BufferID], 0
    
    ; Update pool counters
    dec dword ptr [g_BufferCount]
    
    xor rax, rax
    jmp .Epilogue
    
.Error_Invalid_Index:
    mov rax, -1
    int 3
    jmp .Epilogue
    
.Error_Null_Pointer:
    mov rax, -2
    int 3
    jmp .Epilogue
    
.Epilogue:
    SWARM_PROC_END
Persistent_Buffer_Destroy ENDP

; ==============================================================================
; Persistent_Buffer_GetStats
; Returns buffer pool statistics
; Output: RAX = Total bytes mapped, RCX = Total bytes flushed
; ==============================================================================
ALIGN 16
Persistent_Buffer_GetStats PROC
    mov rax, qword ptr [g_TotalBytesMapped]
    mov rcx, qword ptr [g_TotalBytesFlushed]
    ret
Persistent_Buffer_GetStats ENDP

; ==============================================================================
; Persistent_Buffer_GetMappedPtr
; Returns the persistent mapped pointer for direct AVX-512 writes
; Input: RCX = Buffer index
; Output: RAX = Mapped pointer, NULL on failure
; ==============================================================================
ALIGN 16
Persistent_Buffer_GetMappedPtr PROC
    ; Validate buffer index
    cmp ecx, 0
    jl .Error_Invalid_Index
    mov eax, [g_BufferCount]
    cmp ecx, eax
    jge .Error_Invalid_Index
    
    ; Get buffer
    mov eax, ecx
    imul eax, eax, SIZEOF SwarmV29_Persistent_Buffer
    lea rbx, [g_Buffers + rax]
    
    ; Return mapped pointer
    mov rax, qword ptr [rbx + SwarmV29_Persistent_Buffer.MappedPtr]
    ret
    
.Error_Invalid_Index:
    xor rax, rax
    ret
Persistent_Buffer_GetMappedPtr ENDP

END