; ==============================================================================
; Sovereign_Registry_Manager.asm - Registry Hub Logic
; ==============================================================================

include Sovereign_Common.inc
include Sovereign_Registry.inc

EXTERN g_SovereignHub : SovereignHub

.CODE

; ----------------------------------------------------------------------------
; Sovereign_Registry_Register
; RCX = EntryID
; RDX = pBase
; R8  = Size
; R9  = Flags
; ----------------------------------------------------------------------------
PUBLIC Sovereign_Registry_Register
Sovereign_Registry_Register PROC
    lea rax, g_SovereignHub
    mov r10, [rax + 1024 * 32] ; Count is after 1024 * 32 bytes of entries
    cmp r10, 1024
    jae @@Fail

    ; Calculate entry address: g_SovereignHub.Entries + (Count * 32)
    shl r10, 5                  ; Count * 32
    lea r11, [rax]              ; Hub starts with Entries
    add r11, r10

    mov [r11 + 0], rcx          ; EntryID
    mov [r11 + 8], rdx          ; pBase
    mov [r11 + 16], r8          ; EntrySize
    mov [r11 + 24], r9          ; EntryFlags

    inc qword ptr [rax + 1024 * 32] ; Update Count
    mov rax, 0
    ret

@@Fail:
    mov rax, 1
    ret
Sovereign_Registry_Register ENDP

END
