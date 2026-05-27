; ==============================================================================
; SOVEREIGN_HUD.ASM
; Telemetry HUD Formatter (Option B)
; ==============================================================================
INCLUDE Sovereign_Types.inc

_SOVEREIGN_DATA SEGMENT ALIGN(64) 'DATA'
    PUBLIC g_HUDBuffer
    ; 1KB ASCII buffer formatted by the Engine for the IDE to display directly
    g_HUDBuffer BYTE 1024 DUP(0) 
_SOVEREIGN_DATA ENDS

_TEXT SEGMENT 'CODE'
    PUBLIC Sovereign_Format_HUD

Sovereign_Format_HUD PROC
    ; R15 = Global Context
    ; Prepares a visual ASCII representation of the 16 Lanes and their Cycle_Counts.
    
    push rdi
    push rax
    
    lea rdi, [g_HUDBuffer]
    
    ; 1. Emplace Strict Structural Contract (Header)
    mov rax, 3044554852574152h ; 'RAWRHUD0'
    mov [rdi + SOVEREIGN_HUD_HEADER.Signature], rax
    
    ; 2. Enforce Strict Frame Monotonicity 
    lock inc QWORD PTR [rdi + SOVEREIGN_HUD_HEADER.FrameCount]
    
    ; 3. Data Topology Routing
    mov QWORD PTR [rdi + SOVEREIGN_HUD_HEADER.DataOffset], SIZEOF SOVEREIGN_HUD_HEADER
    mov QWORD PTR [rdi + SOVEREIGN_HUD_HEADER.DataSize], 1024 - SIZEOF SOVEREIGN_HUD_HEADER
    
    ; 4. Format Payload (Placeholder for Hex-to-ASCII serialization)
    ; Here the IDE reads past SIZEOF SOVEREIGN_HUD_HEADER (64 bytes) to get purely safely-mapped text.
    
    pop rax
    pop rdi
    ret
Sovereign_Format_HUD ENDP

_TEXT ENDS
END
