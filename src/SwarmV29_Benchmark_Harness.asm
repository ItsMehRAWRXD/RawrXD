; ==============================================================================
; SwarmV29_Benchmark_Harness.asm
; PHASE-29f: Performance Benchmarking for AZDO Architecture
; Target: Measure bandwidth throughput delta of non-temporal vs cached transfers
; ------------------------------------------------------------------------------
; Architecture:
;   - Links against SwarmV29_VTable_Binding for backend-agnostic dispatch
;   - Measures state change cache hit rate
;   - Quantifies driver call reduction
;   - Validates non-temporal bandwidth improvements
;   - Tracks fence synchronization latency
;
; ABI: Windows x64 (RCX, RDX, R8, R9)
; Dependencies: SwarmV29_Macros.inc, SwarmV29_VTable_Binding.asm
; ==============================================================================

INCLUDE SwarmV29_Macros.inc

; ==============================================================================
; External Functions (From VTable Binding)
; ==============================================================================
EXTERN SwarmV29_Init_Renderer : PROC
EXTERN SwarmV29_Get_Renderer_Stats : PROC
EXTERN SwarmV29_Reset_Renderer_Stats : PROC
EXTERN SwarmV29_Upload_PQC_Data : PROC
EXTERN SwarmV29_Sync_GPU : PROC
EXTERN Modern_GL_GetStateStats : PROC
EXTERN Modern_GL_ResetStats : PROC
EXTERN Persistent_Buffer_Create : PROC
EXTERN Persistent_Buffer_Write : PROC
EXTERN Persistent_Buffer_Write_NonTemporal : PROC
EXTERN Persistent_Buffer_InsertFence : PROC
EXTERN Persistent_Buffer_WaitFence : PROC
EXTERN Persistent_Buffer_Destroy : PROC
EXTERN Persistent_Buffer_GetStats : PROC

; ==============================================================================
; Benchmark Configuration
; ==============================================================================
BENCHMARK_ITERATIONS     EQU 1000
BENCHMARK_WARMUP         EQU 100
BENCHMARK_ENABLE_HW_COUNTERS EQU 0      ; 0 = QPC-only baseline, 1 = enable RDPMC L2/L3 telemetry
BUFFER_SIZE_SMALL        EQU 4096          ; 4KB
BUFFER_SIZE_MEDIUM       EQU 65536         ; 64KB
BUFFER_SIZE_LARGE        EQU 1048576       ; 1MB
BUFFER_SIZE_HUGE         EQU 16777216      ; 16MB

; ==============================================================================
; Benchmark Result Structure (64-byte cache-aligned)
; ==============================================================================
.data
    ALIGN 64
    SwarmV29_Benchmark_Result STRUCT
        Iterations              QWORD ?    ; Number of iterations
        TotalBytesTransferred   QWORD ?    ; Total bytes transferred
        CachedWriteTime         QWORD ?    ; Time for cached writes (QPC)
        NonTemporalWriteTime    QWORD ?    ; Time for non-temporal writes (QPC)
        StateChangesTotal       QWORD ?    ; Total state change requests
        StateChangesSkipped     QWORD ?    ; Skipped (cache hits)
        CacheHitRate            QWORD ?    ; Percentage (0-100)
        FenceInsertTime         QWORD ?    ; Time for fence insertion (QPC)
        FenceWaitTime           QWORD ?    ; Time for fence wait (QPC)
        BandwidthCached         QWORD ?    ; MB/s for cached writes
        BandwidthNonTemporal    QWORD ?    ; MB/s for non-temporal writes
        BandwidthDelta          QWORD ?    ; Percentage improvement
        L2CacheMisses           QWORD ?    ; L2 cache miss counter
        L3CacheMisses           QWORD ?    ; L3 cache miss counter
        Padding                 BYTE 24 dup(?)
    SwarmV29_Benchmark_Result ENDS

    ; Global benchmark results
    ALIGN 64
    g_BenchmarkResults SwarmV29_Benchmark_Result <>
    
    ; QPC frequency
    ALIGN 8
    g_QpcFrequency QWORD 0
    
    ; Test buffers
    ALIGN 64
    g_TestBufferSmall  QWORD 0
    g_TestBufferMedium QWORD 0
    g_TestBufferLarge  QWORD 0
    g_TestBufferHuge   QWORD 0
    
    ; GPU buffer handles
    ALIGN 8
    g_GpuBufferSmall   DWORD 0
    g_GpuBufferMedium  DWORD 0
    g_GpuBufferLarge   DWORD 0
    g_GpuBufferHuge    DWORD 0

.code

; ==============================================================================
; Benchmark_Init
; Initializes benchmark harness and allocates test buffers
; Output: RAX = 0 on success
; ==============================================================================
ALIGN 16
Benchmark_Init PROC
    SWARM_PROC_START Benchmark_Init, <rbx>
    
    ; Get QPC frequency
    sub rsp, 40
    lea rcx, [g_QpcFrequency]
    call QueryPerformanceFrequency
    add rsp, 40
    
    ; Allocate test buffers (aligned to 64 bytes)
    mov rcx, BUFFER_SIZE_SMALL
    mov rdx, 64                         ; Alignment
    call _aligned_malloc
    mov [g_TestBufferSmall], rax
    
    mov rcx, BUFFER_SIZE_MEDIUM
    mov rdx, 64
    call _aligned_malloc
    mov [g_TestBufferMedium], rax
    
    mov rcx, BUFFER_SIZE_LARGE
    mov rdx, 64
    call _aligned_malloc
    mov [g_TestBufferLarge], rax
    
    mov rcx, BUFFER_SIZE_HUGE
    mov rdx, 64
    call _aligned_malloc
    mov [g_TestBufferHuge], rax
    
    ; Fill buffers with test pattern
    mov rdi, [g_TestBufferSmall]
    mov rcx, BUFFER_SIZE_SMALL / 8
    mov rax, 0DEADBEEFCAFEBABEh
    rep stosq
    
    mov rdi, [g_TestBufferMedium]
    mov rcx, BUFFER_SIZE_MEDIUM / 8
    rep stosq
    
    mov rdi, [g_TestBufferLarge]
    mov rcx, BUFFER_SIZE_LARGE / 8
    rep stosq
    
    mov rdi, [g_TestBufferHuge]
    mov rcx, BUFFER_SIZE_HUGE / 8
    rep stosq
    
    ; Initialize GPU buffers
    mov rcx, BUFFER_SIZE_SMALL
    mov rdx, 8892h                       ; GL_ARRAY_BUFFER
    mov r8d, 0042h                       ; GL_MAP_WRITE_BIT | GL_MAP_PERSISTENT_BIT
    call Persistent_Buffer_Create
    mov [g_GpuBufferSmall], eax
    
    mov rcx, BUFFER_SIZE_MEDIUM
    mov rdx, 8892h
    mov r8d, 0042h
    call Persistent_Buffer_Create
    mov [g_GpuBufferMedium], eax
    
    mov rcx, BUFFER_SIZE_LARGE
    mov rdx, 8892h
    mov r8d, 0042h
    call Persistent_Buffer_Create
    mov [g_GpuBufferLarge], eax
    
    mov rcx, BUFFER_SIZE_HUGE
    mov rdx, 8892h
    mov r8d, 0042h
    call Persistent_Buffer_Create
    mov [g_GpuBufferHuge], eax
    
    xor rax, rax
    
    SWARM_PROC_END
Benchmark_Init ENDP

; ==============================================================================
; Benchmark_Cleanup
; Releases all allocated resources
; ==============================================================================
ALIGN 16
Benchmark_Cleanup PROC
    SWARM_PROC_START Benchmark_Cleanup, <>
    
    ; Free test buffers
    mov rcx, [g_TestBufferSmall]
    test rcx, rcx
    jz .Skip_Small
    call _aligned_free
.Skip_Small:
    
    mov rcx, [g_TestBufferMedium]
    test rcx, rcx
    jz .Skip_Medium
    call _aligned_free
.Skip_Medium:
    
    mov rcx, [g_TestBufferLarge]
    test rcx, rcx
    jz .Skip_Large
    call _aligned_free
.Skip_Large:
    
    mov rcx, [g_TestBufferHuge]
    test rcx, rcx
    jz .Skip_Huge
    call _aligned_free
.Skip_Huge:
    
    ; Destroy GPU buffers
    mov ecx, [g_GpuBufferSmall]
    call Persistent_Buffer_Destroy
    
    mov ecx, [g_GpuBufferMedium]
    call Persistent_Buffer_Destroy
    
    mov ecx, [g_GpuBufferLarge]
    call Persistent_Buffer_Destroy
    
    mov ecx, [g_GpuBufferHuge]
    call Persistent_Buffer_Destroy
    
    xor rax, rax
    
    SWARM_PROC_END
Benchmark_Cleanup ENDP

; ==============================================================================
; Benchmark_Cached_Write
; Measures bandwidth for cached writes (vmovdqa64)
; Input: RCX = Buffer index, RDX = Source pointer, R8 = Size, R9 = Iterations
; Output: RAX = Total time in QPC ticks
; ==============================================================================
ALIGN 16
Benchmark_Cached_Write PROC
    SWARM_PROC_START Benchmark_Cached_Write, <rbx, rdi, rsi, r12>
    
    mov rbx, rcx                        ; Buffer index
    mov rsi, rdx                        ; Source pointer
    mov rdi, r8                          ; Size
    mov r12, r9                          ; Iterations
    
    ; Get start time
    sub rsp, 40
    lea rcx, [rsp + 32]
    call QueryPerformanceCounter
    mov rax, [rsp + 32]
    mov rsi, rax                        ; Save start time
    add rsp, 40
    
    ; Warmup iterations
    mov rcx, BENCHMARK_WARMUP
.Warmup_Loop:
    push rcx
    mov rcx, rbx                        ; Buffer index
    mov rdx, [g_TestBufferSmall]        ; Source
    mov r8, rdi                         ; Size
    xor r9, r9                          ; Use cached write
    call SwarmV29_Upload_PQC_Data
    pop rcx
    dec rcx
    jnz .Warmup_Loop
    
    ; Benchmark iterations
    mov rcx, r12
.Benchmark_Loop:
    push rcx
    mov rcx, rbx
    mov rdx, [g_TestBufferSmall]
    mov r8, rdi
    xor r9, r9
    call SwarmV29_Upload_PQC_Data
    pop rcx
    dec rcx
    jnz .Benchmark_Loop
    
    ; Get end time
    sub rsp, 40
    lea rcx, [rsp + 32]
    call QueryPerformanceCounter
    mov rdx, [rsp + 32]
    add rsp, 40
    
    ; Calculate elapsed time
    sub rdx, rsi                        ; End - Start
    mov rax, rdx
    
    SWARM_PROC_END
Benchmark_Cached_Write ENDP

; ==============================================================================
; Benchmark_NonTemporal_Write
; Measures bandwidth for non-temporal writes (vmovntdq)
; Input: RCX = Buffer index, RDX = Source pointer, R8 = Size, R9 = Iterations
; Output: RAX = Total time in QPC ticks
; ==============================================================================
ALIGN 16
Benchmark_NonTemporal_Write PROC
    SWARM_PROC_START Benchmark_NonTemporal_Write, <rbx, rdi, rsi, r12>
    
    mov rbx, rcx                        ; Buffer index
    mov rsi, rdx                        ; Source pointer
    mov rdi, r8                          ; Size
    mov r12, r9                          ; Iterations
    
    ; Get start time
    sub rsp, 40
    lea rcx, [rsp + 32]
    call QueryPerformanceCounter
    mov rax, [rsp + 32]
    mov rsi, rax
    add rsp, 40
    
    ; Warmup iterations
    mov rcx, BENCHMARK_WARMUP
.Warmup_Loop_NT:
    push rcx
    mov rcx, rbx
    mov rdx, [g_TestBufferSmall]
    mov r8, rdi
    mov r9, 1                           ; Use non-temporal write
    call SwarmV29_Upload_PQC_Data
    pop rcx
    dec rcx
    jnz .Warmup_Loop_NT
    
    ; Benchmark iterations
    mov rcx, r12
.Benchmark_Loop_NT:
    push rcx
    mov rcx, rbx
    mov rdx, [g_TestBufferSmall]
    mov r8, rdi
    mov r9, 1
    call SwarmV29_Upload_PQC_Data
    pop rcx
    dec rcx
    jnz .Benchmark_Loop_NT
    
    ; Get end time
    sub rsp, 40
    lea rcx, [rsp + 32]
    call QueryPerformanceCounter
    mov rdx, [rsp + 32]
    add rsp, 40
    
    ; Calculate elapsed time
    sub rdx, rsi
    mov rax, rdx
    
    SWARM_PROC_END
Benchmark_NonTemporal_Write ENDP

; ==============================================================================
; Benchmark_State_Cache
; Measures state change cache hit rate
; Output: RAX = Cache hit percentage (0-100)
; ==============================================================================
ALIGN 16
Benchmark_State_Cache PROC
    SWARM_PROC_START Benchmark_State_Cache, <rbx>
    
    ; Reset stats
    call Modern_GL_ResetStats
    
    ; Simulate state changes
    mov rbx, BENCHMARK_ITERATIONS
    
.State_Loop:
    push rbx
    
    ; Set depth test (should hit cache after first iteration)
    mov rcx, 1                          ; Enable depth test
    call Modern_GL_SetState
    
    ; Set cull mode (should hit cache)
    mov rcx, 2                          ; Back culling
    call Modern_GL_SetState
    
    ; Set blend mode (should hit cache)
    mov rcx, 1                          ; Alpha blending
    call Modern_GL_SetState
    
    pop rbx
    dec rbx
    jnz .State_Loop
    
    ; Get stats
    call Modern_GL_GetStateStats
    ; RAX = Total requests, RCX = Skipped changes
    
    ; Calculate hit rate
    test rax, rax
    jz .Zero_Requests
    
    ; hit_rate = (skipped * 100) / total
    mov rdx, rcx                        ; Skipped
    imul rdx, 100                       ; * 100
    cqo
    div rax                             ; / total
    
    jmp .Epilogue
    
.Zero_Requests:
    xor rax, rax
    
.Epilogue:
    SWARM_PROC_END
Benchmark_State_Cache ENDP

; ==============================================================================
; Benchmark_Fence_Latency
; Measures fence insertion and wait latency
; Input: RCX = Buffer index, RDX = Iterations
; Output: RAX = Average fence latency in QPC ticks
; ==============================================================================
ALIGN 16
Benchmark_Fence_Latency PROC
    SWARM_PROC_START Benchmark_Fence_Latency, <rbx, rdi>
    
    mov rbx, rcx                        ; Buffer index
    mov rdi, rdx                        ; Iterations
    
    ; Get start time
    sub rsp, 40
    lea rcx, [rsp + 32]
    call QueryPerformanceCounter
    mov rsi, [rsp + 32]
    add rsp, 40
    
    ; Benchmark fence operations
    mov rcx, rdi
.Fence_Loop:
    push rcx
    
    ; Insert fence
    mov rcx, rbx
    call Persistent_Buffer_InsertFence
    
    ; Wait for fence
    mov rcx, rbx
    mov rdx, 1000000000                 ; 1 second timeout
    call Persistent_Buffer_WaitFence
    
    pop rcx
    dec rcx
    jnz .Fence_Loop
    
    ; Get end time
    sub rsp, 40
    lea rcx, [rsp + 32]
    call QueryPerformanceCounter
    mov rdx, [rsp + 32]
    add rsp, 40
    
    ; Calculate average
    sub rdx, rsi                        ; Total time
    mov rcx, rdi                        ; Iterations
    cqo
    div rcx                             ; Average time per iteration
    
    SWARM_PROC_END
Benchmark_Fence_Latency ENDP

; ==============================================================================
; Benchmark_ReadL2Misses
; Reads L2 cache miss counter using RDPMC
; Output: RAX = L2 cache miss count (clamped to prevent underflow)
; Note: Uses PMC index 1 (typically L2 misses on Intel)
; ==============================================================================
ALIGN 16
Benchmark_ReadL2Misses PROC
    SWARM_PROC_START Benchmark_ReadL2Misses, <>
    
    ; Serialize execution before reading counter
    lfence
    
    ; Read L2 miss performance counter
    ; ECX = 1 selects the L2 miss counter on most Intel CPUs
    ; For precise counter selection, program the MSR first (not done here)
    mov ecx, 1                          ; L2 Miss counter index
    rdpmc                               ; EDX:EAX = counter value
    
    ; Combine high and low parts
    shl rdx, 32
    or rdx, rax                         ; RDX = Full 64-bit counter
    
    ; Check for underflow (counter wrapped or invalid)
    ; If delta calculation produces negative, clamp to 0
    mov rax, rdx
    
    SWARM_PROC_END
Benchmark_ReadL2Misses ENDP

; ==============================================================================
; Benchmark_ReadL3Misses
; Reads L3 cache miss counter using RDPMC
; Output: RAX = L3 cache miss count (clamped to prevent underflow)
; Note: Uses PMC index 2 (typically L3 misses on Intel)
; ==============================================================================
ALIGN 16
Benchmark_ReadL3Misses PROC
    SWARM_PROC_START Benchmark_ReadL3Misses, <>
    
    ; Serialize execution before reading counter
    lfence
    
    ; Read L3 miss performance counter
    mov ecx, 2                          ; L3 Miss counter index
    rdpmc
    
    ; Combine high and low parts
    shl rdx, 32
    or rdx, rax
    
    mov rax, rdx
    
    SWARM_PROC_END
Benchmark_ReadL3Misses ENDP

; ==============================================================================
; Benchmark_CalculateDelta
; Calculates delta between two counter readings with underflow clamp
; Input: RCX = Initial value, RDX = Final value
; Output: RAX = Delta (clamped to 0 if underflow)
; ==============================================================================
ALIGN 16
Benchmark_CalculateDelta PROC
    SWARM_PROC_START Benchmark_CalculateDelta, <>
    
    ; Calculate delta: Final - Initial
    sub rdx, rcx                        ; RDX = Delta
    
    ; Check for underflow (negative result)
    jge .NoUnderflow
    
    ; Clamp to zero on underflow
    xor rdx, rdx
    
.NoUnderflow:
    mov rax, rdx
    
    SWARM_PROC_END
Benchmark_CalculateDelta ENDP

; ==============================================================================
; Benchmark_Run_All
; Executes all benchmarks and populates results structure
; Output: RAX = Pointer to SwarmV29_Benchmark_Result
; ==============================================================================
ALIGN 16
Benchmark_Run_All PROC
    SWARM_PROC_START Benchmark_Run_All, <rbx, rdi, rsi>
    
    ; Initialize
    call Benchmark_Init
    test rax, rax
    js .Init_Failed
    
    ; Reset results
    lea rdi, [g_BenchmarkResults]
    mov rcx, SIZEOF SwarmV29_Benchmark_Result
    xor eax, eax
    rep stosb

IF BENCHMARK_ENABLE_HW_COUNTERS
    ; Capture initial hardware counter state (before benchmark workload)
    call Benchmark_ReadL2Misses
    mov rbx, rax                        ; Initial L2 misses
    call Benchmark_ReadL3Misses
    mov rsi, rax                        ; Initial L3 misses
ENDIF
    
    ; ========================================================================
    ; Benchmark 1: Cached Write Bandwidth
    ; ========================================================================
    mov rcx, [g_GpuBufferSmall]
    mov rdx, [g_TestBufferSmall]
    mov r8, BUFFER_SIZE_SMALL
    mov r9, BENCHMARK_ITERATIONS
    call Benchmark_Cached_Write
    
    mov [g_BenchmarkResults.CachedWriteTime], rax
    
    ; ========================================================================
    ; Benchmark 2: Non-Temporal Write Bandwidth
    ; ========================================================================
    mov rcx, [g_GpuBufferSmall]
    mov rdx, [g_TestBufferSmall]
    mov r8, BUFFER_SIZE_SMALL
    mov r9, BENCHMARK_ITERATIONS
    call Benchmark_NonTemporal_Write
    
    mov [g_BenchmarkResults.NonTemporalWriteTime], rax
    
    ; ========================================================================
    ; Benchmark 3: State Cache Hit Rate
    ; ========================================================================
    call Benchmark_State_Cache
    mov [g_BenchmarkResults.CacheHitRate], rax
    
    ; ========================================================================
    ; Benchmark 4: Fence Latency
    ; ========================================================================
    mov rcx, [g_GpuBufferSmall]
    mov rdx, BENCHMARK_ITERATIONS
    call Benchmark_Fence_Latency
    mov [g_BenchmarkResults.FenceInsertTime], rax

IF BENCHMARK_ENABLE_HW_COUNTERS
    ; Capture final hardware counter state and store underflow-safe deltas
    call Benchmark_ReadL2Misses
    mov rdx, rax                        ; Final L2
    mov rcx, rbx                        ; Initial L2
    call Benchmark_CalculateDelta
    mov [g_BenchmarkResults.L2CacheMisses], rax

    call Benchmark_ReadL3Misses
    mov rdx, rax                        ; Final L3
    mov rcx, rsi                        ; Initial L3
    call Benchmark_CalculateDelta
    mov [g_BenchmarkResults.L3CacheMisses], rax
ENDIF
    
    ; ========================================================================
    ; Calculate Bandwidth Metrics
    ; ========================================================================
    ; Bandwidth = (Size * Iterations) / Time
    ; Convert to MB/s: (Bytes / Time_QPC) * QPC_Freq / 1048576
    
    ; Cached bandwidth
    mov rax, BUFFER_SIZE_SMALL
    imul rax, BENCHMARK_ITERATIONS
    mov rcx, [g_BenchmarkResults.CachedWriteTime]
    test rcx, rcx
    jz .Skip_Cached_BW
    cqo
    div rcx                              ; Bytes / Time
    mov rcx, [g_QpcFrequency]
    imul rax, rcx                        ; * QPC_Freq
    mov rcx, 1048576
    cqo
    div rcx                              ; / 1048576 (MB)
    mov [g_BenchmarkResults.BandwidthCached], rax
    
.Skip_Cached_BW:
    ; Non-temporal bandwidth
    mov rax, BUFFER_SIZE_SMALL
    imul rax, BENCHMARK_ITERATIONS
    mov rcx, [g_BenchmarkResults.NonTemporalWriteTime]
    test rcx, rcx
    jz .Skip_NT_BW
    cqo
    div rcx
    mov rcx, [g_QpcFrequency]
    imul rax, rcx
    mov rcx, 1048576
    cqo
    div rcx
    mov [g_BenchmarkResults.BandwidthNonTemporal], rax
    
    ; Calculate delta percentage
    mov rax, [g_BenchmarkResults.BandwidthNonTemporal]
    mov rcx, [g_BenchmarkResults.BandwidthCached]
    test rcx, rcx
    jz .Skip_Delta
    sub rax, rcx                         ; Delta
    imul rax, 100                       ; * 100
    cqo
    div rcx                              ; / Cached
    mov [g_BenchmarkResults.BandwidthDelta], rax
    
.Skip_NT_BW:
.Skip_Delta:
    ; Get renderer stats
    call SwarmV29_Get_Renderer_Stats
    mov [g_BenchmarkResults.StateChangesTotal], rax
    mov [g_BenchmarkResults.StateChangesSkipped], rcx
    
    ; Set iterations
    mov qword ptr [g_BenchmarkResults.Iterations], BENCHMARK_ITERATIONS
    
    ; Calculate total bytes transferred
    mov rax, BUFFER_SIZE_SMALL
    imul rax, BENCHMARK_ITERATIONS
    imul rax, 2                          ; Cached + Non-temporal
    mov [g_BenchmarkResults.TotalBytesTransferred], rax
    
    ; Cleanup
    call Benchmark_Cleanup
    
    ; Return pointer to results
    lea rax, [g_BenchmarkResults]
    jmp .Epilogue
    
.Init_Failed:
    mov rax, -1
    
.Epilogue:
    SWARM_PROC_END
Benchmark_Run_All ENDP

; ==============================================================================
; Benchmark_Print_Results
; Prints benchmark results to console (for debugging)
; Input: RCX = Pointer to SwarmV29_Benchmark_Result
; ==============================================================================
ALIGN 16
Benchmark_Print_Results PROC
    SWARM_PROC_START Benchmark_Print_Results, <>
    
    ; TODO: Implement console output
    ; For now, just return the pointer
    
    mov rax, rcx
    
    SWARM_PROC_END
Benchmark_Print_Results ENDP

; ==============================================================================
; Benchmark_Get_Results
; Returns pointer to benchmark results structure
; Output: RAX = Pointer to SwarmV29_Benchmark_Result
; ==============================================================================
ALIGN 16
Benchmark_Get_Results PROC
    lea rax, [g_BenchmarkResults]
    ret
Benchmark_Get_Results ENDP

END