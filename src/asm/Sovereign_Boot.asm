; ==============================================================================
; SOVEREIGN BOOTSTRAP (Bare Metal Entry)
; File: Sovereign_Boot.asm
; ==============================================================================

include Sovereign_Common.inc
include Sovereign_FrameABI.inc

EXTERN Sovereign_Runtime_Init:PROC
EXTERN Sovereign_Setup_Hardware_Watchdog:PROC

.DATA
    g_GDT_Descriptor QWORD 0 
    g_Sovereign_Stack_Base QWORD 07C00h 
    g_Device_Buffer_Base QWORD 0100000h 

.CODE
; Entry point from Bootloader/Firmware
PUBLIC _start
_start PROC
    ; 1. Disable Interrupts
    cli
    
    ; 2. Initialize Minimal GDT (Global Descriptor Table)
    ; Mandatory for 64-bit long mode execution
    ; lgdt fword ptr [g_GDT_Descriptor]
    
    ; 3. Setup Stack (Sovereign Arena starts here)
    mov rsp, [g_Sovereign_Stack_Base]
    
    ; 4. Initialize Hardware Watchdog (NMI - The "++" Factor)
    ; Map the Supervisor Loop to the Non-Maskable Interrupt Vector
    call Sovereign_Setup_Hardware_Watchdog
    
    ; 5. Jump to Orchestrator
    ; RCX = Mapped Base, RDX = Node ID 0
    mov rcx, [g_Device_Buffer_Base] 
    xor rdx, rdx
    call Sovereign_Runtime_Init
    
    ; Infinite loop (Kernel idle)
@@Idle:
    hlt
    jmp @@Idle
_start ENDP

END
