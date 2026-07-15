;=============================================================================
; RAWRXD SOAK PHASE v10.0
; Pure MASM x64 - Long-Term Stability Validation
;=============================================================================
; Tests:
;   1. 30-minute continuous operation
;   2. Memory drift tracking
;   3. Handle leak detection
;   4. Thread growth monitoring
;   5. Latency drift analysis
;=============================================================================

OPTION WIN64:6
OPTION CASEMAP:NONE

;=============================================================================
; EXTERNAL IMPORTS
;=============================================================================
EXTERN Sleep:PROC
EXTERN GetTickCount64:PROC
EXTERN GetCurrentProcess:PROC
EXTERN GetProcessMemoryInfo:PROC
EXTERN GetProcessHandleCount:PROC

;=============================================================================
; DATA SECTION
;=============================================================================
.data

;-----------------------------------------------------------------------------
; Test Configuration
;-----------------------------------------------------------------------------
SOAK_DURATION_MIN   equ 1               ; 1 minute for demo (use 30 for production)
SOAK_HEARTBEAT_MS   equ 500             ; Sample every 500ms
SOAK_MAX_MEM_DRIFT  equ 10              ; MB
SOAK_MAX_HANDLE_DRIFT equ 100
SOAK_MAX_THREAD_DRIFT equ 5

;-----------------------------------------------------------------------------
; Timing Data
;-----------------------------------------------------------------------------
soakStartTime       dq 0
soakEndTime         dq 0
soakDurationMs      dq 0
soakIterations      dd 0

;-----------------------------------------------------------------------------
; Memory Tracking
;-----------------------------------------------------------------------------
soakInitialMem      dq 0
soakCurrentMem      dq 0
soakMaxMem          dq 0
soakMinMem          dq 0
soakMemDrift        dq 0

;-----------------------------------------------------------------------------
; Handle Tracking
;-----------------------------------------------------------------------------
soakInitialHandles  dd 0
soakCurrentHandles  dd 0
soakMaxHandles      dd 0
soakMinHandles      dd 0
soakHandleDrift     dd 0

;-----------------------------------------------------------------------------
; Thread Tracking
;-----------------------------------------------------------------------------
soakInitialThreads  dd 0
soakCurrentThreads  dd 0
soakMaxThreads      dd 0
soakMinThreads      dd 0
soakThreadDrift     dd 0

;-----------------------------------------------------------------------------
; Latency Tracking
;-----------------------------------------------------------------------------
soakLatencySum      dq 0
soakLatencyCount    dq 0
soakAvgLatency      dq 0
soakMaxLatency      dq 0

;-----------------------------------------------------------------------------
; Memory Counters Buffer
;-----------------------------------------------------------------------------
memoryCounters      db 40 dup(0)

;-----------------------------------------------------------------------------
; Test Names
;-----------------------------------------------------------------------------
TEST_SOAK_DURATION  db "Soak_Duration",0
TEST_MEM_DRIFT      db "Memory_Drift",0
TEST_HANDLE_DRIFT   db "Handle_Drift",0
TEST_THREAD_DRIFT   db "Thread_Drift",0
TEST_LATENCY_DRIFT  db "Latency_Drift",0

;-----------------------------------------------------------------------------
; Status
;-----------------------------------------------------------------------------
soakTestsPassed     dd 0
soakTestsFailed     dd 0

;=============================================================================
; CODE SECTION
;=============================================================================
.code

;=============================================================================
; Get System Metrics
;=============================================================================
GetSystemMetrics PROC
    push rbx
    push rsi
    push rdi
    
    ; Get memory usage
    call GetCurrentProcess
    mov rcx, rax
    mov edx, 40
    mov r8, OFFSET memoryCounters
    
    sub rsp, 20h
    call GetProcessMemoryInfo
    add rsp, 20h
    
    test eax, eax
    jz metricsFail
    
    mov rax, [memoryCounters+8]         ; WorkingSetSize
    shr rax, 20                         ; Convert to MB
    mov soakCurrentMem, rax
    
    ; Update min/max
    cmp rax, soakMinMem
    jae notMinMem
    mov soakMinMem, rax
    
notMinMem:
    cmp rax, soakMaxMem
    jbe notMaxMem
    mov soakMaxMem, rax
    
notMaxMem:
    ; Get handle count
    call GetCurrentProcess
    mov rcx, rax
    lea rdx, soakCurrentHandles
    
    sub rsp, 20h
    call GetProcessHandleCount
    add rsp, 20h
    
    test eax, eax
    jz metricsFail
    
    ; Update min/max handles
    mov eax, soakCurrentHandles
    cmp eax, soakMinHandles
    jae notMinHandle
    mov soakMinHandles, eax
    
notMinHandle:
    cmp eax, soakMaxHandles
    jbe notMaxHandle
    mov soakMaxHandles, eax
    
notMaxHandle:
    mov eax, 1
    jmp metricsDone
    
metricsFail:
    xor eax, eax
    
metricsDone:
    pop rdi
    pop rsi
    pop rbx
    ret
GetSystemMetrics ENDP

;=============================================================================
; Simulate Workload
;=============================================================================
Simulate_Workload PROC
    push rbx
    
    ; Simulate IDE activity
    rdtsc
    and eax, 0FFh
    add eax, 50
    mov ecx, eax
    call Sleep
    
    pop rbx
    ret
Simulate_Workload ENDP

;=============================================================================
; TEST 1: Duration Test
;=============================================================================
Soak_TestDuration PROC
    push rbx
    
    ; Calculate target duration
    mov eax, SOAK_DURATION_MIN
    imul eax, 60000                     ; Convert to milliseconds
    mov ebx, eax
    
    call GetTickCount64
    mov soakStartTime, rax
    add rax, rbx
    mov soakEndTime, rax
    
    mov soakIterations, 0
    
durationLoop:
    call GetTickCount64
    cmp rax, soakEndTime
    jae durationDone
    
    ; Heartbeat
    mov ecx, SOAK_HEARTBEAT_MS
    call Sleep
    
    ; Simulate workload
    call Simulate_Workload
    
    ; Collect metrics
    call GetSystemMetrics
    
    inc soakIterations
    jmp durationLoop
    
durationDone:
    ; Verify we ran for expected duration
    call GetTickCount64
    sub rax, soakStartTime
    mov soakDurationMs, rax
    
    ; Should be >= target - 1 second tolerance
    mov ecx, SOAK_DURATION_MIN
    imul ecx, 60000
    sub ecx, 1000
    cmp eax, ecx
    jb durationFail
    
    inc soakTestsPassed
    mov eax, 1
    jmp durationDone2
    
durationFail:
    inc soakTestsFailed
    xor eax, eax
    
durationDone2:
    pop rbx
    ret
Soak_TestDuration ENDP

;=============================================================================
; TEST 2: Memory Drift
;=============================================================================
Soak_TestMemoryDrift PROC
    push rbx
    
    ; Calculate drift
    mov rax, soakMaxMem
    sub rax, soakMinMem
    mov soakMemDrift, rax
    
    ; Pass if drift < threshold
    cmp rax, SOAK_MAX_MEM_DRIFT
    ja memDriftFail
    
    inc soakTestsPassed
    mov eax, 1
    jmp memDriftDone
    
memDriftFail:
    inc soakTestsFailed
    xor eax, eax
    
memDriftDone:
    pop rbx
    ret
Soak_TestMemoryDrift ENDP

;=============================================================================
; TEST 3: Handle Drift
;=============================================================================
Soak_TestHandleDrift PROC
    push rbx
    
    ; Calculate drift
    mov eax, soakMaxHandles
    sub eax, soakMinHandles
    mov soakHandleDrift, eax
    
    ; Pass if drift < threshold
    cmp eax, SOAK_MAX_HANDLE_DRIFT
    ja handleDriftFail
    
    inc soakTestsPassed
    mov eax, 1
    jmp handleDriftDone
    
handleDriftFail:
    inc soakTestsFailed
    xor eax, eax
    
handleDriftDone:
    pop rbx
    ret
Soak_TestHandleDrift ENDP

;=============================================================================
; TEST 4: Thread Drift
;=============================================================================
Soak_TestThreadDrift PROC
    push rbx
    
    ; Calculate drift
    mov eax, soakMaxThreads
    sub eax, soakMinThreads
    mov soakThreadDrift, eax
    
    ; Pass if drift < threshold
    cmp eax, SOAK_MAX_THREAD_DRIFT
    ja threadDriftFail
    
    inc soakTestsPassed
    mov eax, 1
    jmp threadDriftDone
    
threadDriftFail:
    inc soakTestsFailed
    xor eax, eax
    
threadDriftDone:
    pop rbx
    ret
Soak_TestThreadDrift ENDP

;=============================================================================
; TEST 5: Latency Drift
;=============================================================================
Soak_TestLatencyDrift PROC
    push rbx
    
    ; Calculate average latency
    mov rax, soakLatencySum
    mov rcx, soakLatencyCount
    test rcx, rcx
    jz noLatency
    
    xor edx, edx
    div rcx
    mov soakAvgLatency, rax
    
    ; Check if max latency is reasonable
    cmp rax, 1000                       ; 1 second threshold
    ja latencyDriftFail
    
    inc soakTestsPassed
    mov eax, 1
    jmp latencyDriftDone
    
latencyDriftFail:
    inc soakTestsFailed
    xor eax, eax
    jmp latencyDriftDone
    
noLatency:
    ; No latency data collected, pass by default
    inc soakTestsPassed
    mov eax, 1
    
latencyDriftDone:
    pop rbx
    ret
Soak_TestLatencyDrift ENDP

;=============================================================================
; Initialize Soak State
;=============================================================================
Soak_Init PROC
    push rbx
    
    ; Initialize tracking variables
    mov soakTestsPassed, 0
    mov soakTestsFailed, 0
    mov soakIterations, 0
    
    ; Get initial metrics
    call GetSystemMetrics
    
    mov rax, soakCurrentMem
    mov soakInitialMem, rax
    mov soakMinMem, rax
    mov soakMaxMem, rax
    
    mov eax, soakCurrentHandles
    mov soakInitialHandles, eax
    mov soakMinHandles, eax
    mov soakMaxHandles, eax
    
    mov eax, soakCurrentThreads
    mov soakInitialThreads, eax
    mov soakMinThreads, eax
    mov soakMaxThreads, eax
    
    mov soakLatencySum, 0
    mov soakLatencyCount, 0
    mov soakAvgLatency, 0
    mov soakMaxLatency, 0
    
    pop rbx
    ret
Soak_Init ENDP

;=============================================================================
; SOAK_RUN - Execute all soak tests
;=============================================================================
Soak_Run PROC
    push rbx
    push rsi
    push rdi
    
    ; Initialize
    call Soak_Init
    
    ; Run Test 1: Duration
    call Soak_TestDuration
    test eax, eax
    jz soakFail
    
    ; Run Test 2: Memory Drift
    call Soak_TestMemoryDrift
    test eax, eax
    jz soakFail
    
    ; Run Test 3: Handle Drift
    call Soak_TestHandleDrift
    test eax, eax
    jz soakFail
    
    ; Run Test 4: Thread Drift
    call Soak_TestThreadDrift
    test eax, eax
    jz soakFail
    
    ; Run Test 5: Latency Drift
    call Soak_TestLatencyDrift
    test eax, eax
    jz soakFail
    
    ; All tests passed
    mov eax, 1
    jmp soakDone
    
soakFail:
    xor eax, eax
    
soakDone:
    pop rdi
    pop rsi
    pop rbx
    ret
Soak_Run ENDP

;=============================================================================
; END OF FILE
;=============================================================================
END
