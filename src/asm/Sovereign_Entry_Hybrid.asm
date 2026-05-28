; ==============================================================================
; SOVEREIGN ENTRY HYBRID (The Fusion Layer)
; File: Sovereign_Entry_Hybrid.asm
; Role: Hijacks CRT execution, initializes Arena, launches Scheduler
; ==============================================================================

EXTERN Sovereign_Fabric_Loop:PROC
EXTERN Sovereign_Setup_NMI:PROC

.CODE

PUBLIC _start
_start PROC
    ; 1. Suppress CRT Entry
    ; We are now the absolute owners of the process memory.
    
    ; 2. Initialize Sovereign Arena (Raw syscall to NtAllocateVirtualMemory)
    ; This bypasses malloc() and creates the non-paged pool for our Fabric
    mov r8, 0100000h        ; Base: 0x100000
    mov r9, 04000000h       ; Size: 64MB
    call Setup_Arena_Physical_Mapping
    
    ; 3. Setup Hardware Governance (The NMI Watchdog)
    call Sovereign_Setup_NMI
    
    ; 4. Enter Fabric Scheduler
    ; We do not return to the OS. We spin the Scheduler directly.
    jmp Sovereign_Fabric_Loop
_start ENDP

; Internal helper: Direct syscall to reserve memory
Setup_Arena_Physical_Mapping PROC
    ; Wrapper for NtAllocateVirtualMemory
    ; (Syscall index varies by Win10/11 version, usually 0x18)
    mov r10, rcx
    mov eax, 018h           ; NtAllocateVirtualMemory Index
    syscall
    ret
Setup_Arena_Physical_Mapping ENDP

END