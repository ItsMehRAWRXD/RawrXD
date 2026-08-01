; =====================================================================================
; PLATFORM IP INFRASTRUCTURE SPECIFICATION: Core Backend Low-Overhead Registry Table
; Target Architecture: Windows x64 (AMD64)
; Compiler Target: MASM (ml64.exe)
; =====================================================================================

.DATA

ALIGN 8
; --- Core Registry Memory Block Allocation Structure Layout ---
; Offset 0x00: DWORD Active Backend Identification Value Index (1=PS, 2=BM, 3=Remote, 4=Sandbox)
; Offset 0x04: DWORD Driver Operations Flags Bitmask
; Offset 0x08: QWORD Capability Feature Support Matrix Fields
ActiveBackendID   DWORD 2                ; Defaults out of factory initialization states to 2 (BareMetal)
RegistryFlags     DWORD 00000001h        ; Baseline System State Flag Bits
CapabilityMatrix  QWORD 00000000000000FFh; Full hardware support bitmask parameters allocation block

.CODE

; -------------------------------------------------------------------------------------
; API EXPORT FUNCTION: RawrXD_SetActiveBackend
; Register Allocation Map Input: ECX - Target Backend Identifier Code Integer
; -------------------------------------------------------------------------------------
RawrXD_SetActiveBackend PROC
    mov [ActiveBackendID], ecx           ; Commit active identifier directly to memory data slice
    ret
RawrXD_SetActiveBackend ENDP

; -------------------------------------------------------------------------------------
; API EXPORT FUNCTION: RawrXD_GetActiveBackend
; Output Allocation Target: EAX - Returns active identifier value configuration index
; -------------------------------------------------------------------------------------
RawrXD_GetActiveBackend PROC
    mov eax, [ActiveBackendID]           ; Read configuration state variable context 
    ret
RawrXD_GetActiveBackend ENDP

END
