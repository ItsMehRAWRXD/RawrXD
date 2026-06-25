;=============================================================================
; RAWRXD SMOKE PHASE v10.0
; Pure MASM x64 - Boot Correctness Validation
;=============================================================================
; Tests:
;   1. Binary existence check
;   2. Process launch capability
;   3. Memory baseline validation
;   4. Thread/handle sanity
;   5. 5-second stability window
;=============================================================================

OPTION WIN64:6
OPTION CASEMAP:NONE

;=============================================================================
; EXTERNAL IMPORTS
;=============================================================================
EXTERN GetFileAttributesA:PROC
EXTERN CreateProcessA:PROC
EXTERN WaitForSingleObject:PROC
EXTERN GetExitCodeProcess:PROC
EXTERN CloseHandle:PROC
EXTERN Sleep:PROC
EXTERN GetCurrentProcess:PROC
EXTERN GetProcessMemoryInfo:PROC
EXTERN GetProcessHandleCount:PROC
EXTERN GetCurrentProcessId:PROC
EXTERN OpenProcess:PROC
EXTERN VirtualAlloc:PROC
EXTERN VirtualFree:PROC

;=============================================================================
; DATA SECTION
;=============================================================================
.data

;-----------------------------------------------------------------------------
; Test Configuration
;-----------------------------------------------------------------------------
SMOKE_BINARY_PATH   db "d:\\rawrxd\\RawrXD-Win32IDE.exe",0
SMOKE_TIMEOUT_MS    equ 5000
SMOKE_MEMORY_MAX_MB equ 150

;-----------------------------------------------------------------------------
; Test Results
;-----------------------------------------------------------------------------
smokeTestCount      dd 5
smokeTestsPassed    dd 0
smokeTestsFailed    dd 0

;-----------------------------------------------------------------------------
; Process Info
;-----------------------------------------------------------------------------
startupInfo         db 104 dup(0)       ; STARTUPINFOA (68h bytes)
processInfo         db 24 dup(0)        ; PROCESS_INFORMATION (18h bytes)
hSmokeProcess       dq 0
hSmokeThread        dq 0
dwProcessId         dd 0
dwThreadId          dd 0

;-----------------------------------------------------------------------------
; Memory Info Structure (PROCESS_MEMORY_COUNTERS)
;-----------------------------------------------------------------------------
memoryCounters      db 40 dup(0)        ; cb + PageFaultCount + WorkingSetSize + ...

;-----------------------------------------------------------------------------
; Status Strings
;-----------------------------------------------------------------------------
TEST_BINARY         db "BinaryExists",0
TEST_LAUNCH         db "ProcessLaunch",0
TEST_MEMORY         db "MemoryBaseline",0
TEST_HANDLES        db "HandleSanity",0
TEST_STABILITY      db "StabilityWindow",0

;-----------------------------------------------------------------------------
; Error Tracking
;-----------------------------------------------------------------------------
lastErrorCode       dd 0

;=============================================================================
; CODE SECTION
;=============================================================================
.code

;=============================================================================
; TEST 1: Binary Existence Check
;=============================================================================
Smoke_TestBinary PROC
    push rbx
    
    ; Check if binary exists
    mov rcx, OFFSET SMOKE_BINARY_PATH
    call GetFileAttributesA
    
    cmp rax, -1
    je binaryFail
    
    ; Check if it's not a directory
    test rax, 10h           ; FILE_ATTRIBUTE_DIRECTORY
    jnz binaryFail
    
    inc smokeTestsPassed
    mov eax, 1
    jmp binaryDone
    
binaryFail:
    inc smokeTestsFailed
    xor eax, eax
    
binaryDone:
    pop rbx
    ret
Smoke_TestBinary ENDP

;=============================================================================
; TEST 2: Process Launch Capability
;=============================================================================
Smoke_TestLaunch PROC
    push rbx
    push rsi
    push rdi
    
    ; Initialize STARTUPINFO
    mov rdi, OFFSET startupInfo
    mov ecx, 104
    xor eax, eax
    rep stosb
    
    mov dword ptr [startupInfo], 68h    ; cb = sizeof(STARTUPINFOA)
    
    ; Initialize PROCESS_INFORMATION
    mov rdi, OFFSET processInfo
    mov ecx, 24
    xor eax, eax
    rep stosb
    
    ; Create process
    mov rcx, OFFSET SMOKE_BINARY_PATH   ; lpApplicationName
    xor edx, edx                        ; lpCommandLine
    xor r8d, r8d                        ; lpProcessAttributes
    xor r9d, r9d                        ; lpThreadAttributes
    mov qword ptr [rsp+28h], 0          ; bInheritHandles
    mov qword ptr [rsp+30h], 0          ; dwCreationFlags (CREATE_NO_WINDOW)
    mov qword ptr [rsp+38h], 0          ; lpEnvironment
    mov qword ptr [rsp+40h], 0          ; lpCurrentDirectory
    mov r10, OFFSET startupInfo
    mov qword ptr [rsp+48h], r10        ; lpStartupInfo
    mov r11, OFFSET processInfo
    mov qword ptr [rsp+50h], r11        ; lpProcessInformation
    
    sub rsp, 58h
    call CreateProcessA
    add rsp, 58h
    
    test eax, eax
    jz launchFail
    
    ; Save handles
    mov rax, [processInfo]              ; hProcess
    mov hSmokeProcess, rax
    mov rax, [processInfo+8]            ; hThread
    mov hSmokeThread, rax
    mov eax, [processInfo+16]           ; dwProcessId
    mov dwProcessId, eax
    mov eax, [processInfo+20]           ; dwThreadId
    mov dwThreadId, eax
    
    ; Wait briefly to ensure it started
    mov rcx, hSmokeProcess
    mov edx, 1000                       ; 1 second
    call WaitForSingleObject
    
    ; Check if still running (timeout = 0x102)
    cmp eax, 102h
    jne launchFail
    
    inc smokeTestsPassed
    mov eax, 1
    jmp launchDone
    
launchFail:
    ; Cleanup if handles exist
    mov rcx, hSmokeProcess
    test rcx, rcx
    jz noProcess
    call CloseHandle
    xor eax, eax
    mov hSmokeProcess, rax
    
noProcess:
    mov rcx, hSmokeThread
    test rcx, rcx
    jz noThread
    call CloseHandle
    xor eax, eax
    mov hSmokeThread, rax
    
noThread:
    inc smokeTestsFailed
    xor eax, eax
    
launchDone:
    pop rdi
    pop rsi
    pop rbx
    ret
Smoke_TestLaunch ENDP

;=============================================================================
; TEST 3: Memory Baseline Validation
;=============================================================================
Smoke_TestMemory PROC
    push rbx
    push rsi
    push rdi
    
    ; Check if we have a process to monitor
    mov rcx, hSmokeProcess
    test rcx, rcx
    jz memoryFail
    
    ; Wait a moment for process to initialize
    mov ecx, 500
    call Sleep
    
    ; Get memory info
    mov rcx, hSmokeProcess
    mov edx, 40                         ; cb
    mov r8, OFFSET memoryCounters
    
    sub rsp, 20h
    call GetProcessMemoryInfo
    add rsp, 20h
    
    test eax, eax
    jz memoryFail
    
    ; Check working set size (offset 8 in PROCESS_MEMORY_COUNTERS)
    mov rax, [memoryCounters+8]         ; WorkingSetSize
    shr rax, 20                         ; Convert to MB
    
    cmp eax, SMOKE_MEMORY_MAX_MB
    ja memoryFail
    
    inc smokeTestsPassed
    mov eax, 1
    jmp memoryDone
    
memoryFail:
    inc smokeTestsFailed
    xor eax, eax
    
memoryDone:
    pop rdi
    pop rsi
    pop rbx
    ret
Smoke_TestMemory ENDP

;=============================================================================
; TEST 4: Handle Sanity Check
;=============================================================================
Smoke_TestHandles PROC
    push rbx
    
    ; Check if we have a process to monitor
    mov rcx, hSmokeProcess
    test rcx, rcx
    jz handlesFail
    
    ; Get handle count
    mov rcx, hSmokeProcess
    lea rdx, dword ptr [rsp+28h]
    
    sub rsp, 30h
    call GetProcessHandleCount
    add rsp, 30h
    
    test eax, eax
    jz handlesFail
    
    ; Reasonable handle count check (should be < 10000)
    mov eax, [rsp+28h]
    cmp eax, 10000
    ja handlesFail
    
    inc smokeTestsPassed
    mov eax, 1
    jmp handlesDone
    
handlesFail:
    inc smokeTestsFailed
    xor eax, eax
    
handlesDone:
    ret
Smoke_TestHandles ENDP

;=============================================================================
; TEST 5: 5-Second Stability Window
;=============================================================================
Smoke_TestStability PROC
    push rbx
    push rsi
    push rdi
    
    ; Check if we have a process to monitor
    mov rcx, hSmokeProcess
    test rcx, rcx
    jz stabilityFail
    
    ; Monitor for 5 seconds
    mov ebx, 5                          ; 5 iterations of 1 second
    
stabilityLoop:
    ; Wait 1 second
    mov ecx, 1000
    call Sleep
    
    ; Check if process still running
    mov rcx, hSmokeProcess
    mov edx, 0                          ; Wait 0 (check only)
    call WaitForSingleObject
    
    ; If not timeout, process exited
    cmp eax, 102h
    jne stabilityFail
    
    dec ebx
    jnz stabilityLoop
    
    ; All 5 seconds passed
    inc smokeTestsPassed
    mov eax, 1
    jmp stabilityDone
    
stabilityFail:
    inc smokeTestsFailed
    xor eax, eax
    
stabilityDone:
    ; Cleanup process handles
    mov rcx, hSmokeProcess
    test rcx, rcx
    jz noProcessCleanup
    call CloseHandle
    xor eax, eax
    mov hSmokeProcess, rax
    
noProcessCleanup:
    mov rcx, hSmokeThread
    test rcx, rcx
    jz noThreadCleanup
    call CloseHandle
    xor eax, eax
    mov hSmokeThread, rax
    
noThreadCleanup:
    pop rdi
    pop rsi
    pop rbx
    ret
Smoke_TestStability ENDP

;=============================================================================
; SMOKE_RUN - Execute all smoke tests
;=============================================================================
Smoke_Run PROC
    push rbx
    push rsi
    push rdi
    
    ; Reset counters
    mov smokeTestsPassed, 0
    mov smokeTestsFailed, 0
    
    ; Run Test 1: Binary Existence
    call Smoke_TestBinary
    test eax, eax
    jz smokeFail
    
    ; Run Test 2: Process Launch
    call Smoke_TestLaunch
    test eax, eax
    jz smokeFail
    
    ; Run Test 3: Memory Baseline
    call Smoke_TestMemory
    test eax, eax
    jz smokeFail
    
    ; Run Test 4: Handle Sanity
    call Smoke_TestHandles
    test eax, eax
    jz smokeFail
    
    ; Run Test 5: Stability Window
    call Smoke_TestStability
    test eax, eax
    jz smokeFail
    
    ; All tests passed
    mov eax, 1
    jmp smokeDone
    
smokeFail:
    ; Cleanup any remaining handles
    mov rcx, hSmokeProcess
    test rcx, rcx
    jz noCleanup1
    call CloseHandle
    
noCleanup1:
    mov rcx, hSmokeThread
    test rcx, rcx
    jz noCleanup2
    call CloseHandle
    
noCleanup2:
    xor eax, eax
    
smokeDone:
    pop rdi
    pop rsi
    pop rbx
    ret
Smoke_Run ENDP

;=============================================================================
; END OF FILE
;=============================================================================
END
