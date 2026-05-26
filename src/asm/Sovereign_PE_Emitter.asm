; =============================================================================
; Sovereign_PE_Emitter.asm - The Sovereign OS Binary Synthesizer
; Purpose: Manual construction of PE64 structures for "Sealing" runtime state.
; Architecture: x64 MASM, Zero-Dependency.
; =============================================================================

.CODE

; --- PE Structure Definitions (MASM Style) ---

; Using equates for offsets to ensure zero-dependency on external headers

; DOS Header Size: 64 Bytes
; NT Header Size: (4 + 20 + 240) = 264 Bytes
; Section Header Size: 40 Bytes per section

; -----------------------------------------------------------------------------------------
; XR_Emit_PE_Header
; Inputs:  RCX = Destination Buffer (Must be at least 1024 bytes)
;          RDX = EntryPoint RVA
;          R8  = ImageBase
; Outputs: RAX = Bytes Written (Size of total headers)
; -----------------------------------------------------------------------------------------
PUBLIC XR_Emit_PE_Header
XR_Emit_PE_Header PROC
    push    rdi
    mov     rdi, rcx                    ; RDI = DestBuf
    
    ; [1] DOS Header
    mov     word ptr [rdi], 5A4Dh       ; e_magic = 'MZ'
    mov     word ptr [rdi + 60], 80h    ; e_lfanew = 0x80 (Offset to PE Header)
    
    ; Zero out the rest of the DOS header and stub area
    mov     ecx, 15                     ; (128 - 64) / 4 = 16 dwords, minus the e_lfanew we wrote
    lea     rax, [rdi + 2]
@@zero_dos:
    mov     dword ptr [rax], 0
    add     rax, 4
    loop    @@zero_dos

    add     rdi, 80h                    ; Advance to e_lfanew offset

    ; [2] PE Signature
    mov     dword ptr [rdi], 00004550h  ; Signature = 'PE\0\0'
    add     rdi, 4

    ; [3] Image File Header (20 Bytes)
    mov     word ptr [rdi], 8664h       ; Machine = AMD64
    mov     word ptr [rdi + 2], 3       ; NumberOfSections = 3 (.text, .data, .rdata)
    mov     dword ptr [rdi + 4], 0      ; TimeDateStamp
    mov     dword ptr [rdi + 8], 0      ; PointerToSymbolTable
    mov     dword ptr [rdi + 12], 0     ; NumberOfSymbols
    mov     word ptr [rdi + 16], 0F0h   ; SizeOfOptionalHeader = 240 (PE32+)
    mov     word ptr [rdi + 18], 0022h  ; Characteristics = EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
    add     rdi, 20

    ; [4] Optional Header (240 Bytes for PE64)
    mov     word ptr [rdi], 020Bh       ; Magic = PE32+ (64-bit)
    mov     byte ptr [rdi + 2], 1       ; MajorLinkerVersion
    mov     byte ptr [rdi + 3], 0       ; MinorLinkerVersion
    mov     dword ptr [rdi + 4], 1000h  ; SizeOfCode
    mov     dword ptr [rdi + 8], 1000h  ; SizeOfInitializedData
    mov     dword ptr [rdi + 12], 0     ; SizeOfUninitializedData
    mov     dword ptr [rdi + 16], edx   ; AddressOfEntryPoint (RVA)
    mov     dword ptr [rdi + 20], 1000h ; BaseOfCode (RVA)
    
    ; PE64 specific ImageBase (8 bytes)
    mov     qword ptr [rdi + 24], r8    ; ImageBase
    
    mov     dword ptr [rdi + 32], 1000h ; SectionAlignment = 4096
    mov     dword ptr [rdi + 36], 200h  ; FileAlignment = 512
    
    mov     word ptr [rdi + 40], 6      ; MajorOSVersion (Win 10+)
    mov     word ptr [rdi + 42], 0
    mov     word ptr [rdi + 44], 0      ; MajorImageVersion
    mov     word ptr [rdi + 46], 0
    mov     word ptr [rdi + 48], 6      ; MajorSubsystemVersion
    mov     word ptr [rdi + 50], 0
    mov     dword ptr [rdi + 52], 0     ; Win32VersionValue
    
    mov     dword ptr [rdi + 56], 4000h ; SizeOfImage (Adjusted later)
    mov     dword ptr [rdi + 60], 400h  ; SizeOfHeaders
    mov     dword ptr [rdi + 64], 0     ; CheckSum
    mov     word ptr [rdi + 68], 3      ; Subsystem = CONSOLE
    mov     word ptr [rdi + 70], 8140h  ; DllCharacteristics = HIGH_ENTROPY_VA | DYNAMIC_BASE | NX_COMPAT | TERMINAL_SERVER_AWARE
    
    mov     qword ptr [rdi + 72], 100000h ; SizeOfStackReserve
    mov     qword ptr [rdi + 80], 1000h   ; SizeOfStackCommit
    mov     qword ptr [rdi + 88], 100000h ; SizeOfHeapReserve
    mov     qword ptr [rdi + 96], 1000h   ; SizeOfHeapCommit
    mov     dword ptr [rdi + 104], 0      ; LoaderFlags
    mov     dword ptr [rdi + 108], 10h    ; NumberOfRvaAndSizes (Export, Import, Resource, Exception, etc.)
    
    add     rdi, 240                    ; Advance past Optional Header

    ; [5] Section Headers (40 Bytes each)
    ; .text
    mov     rax, 00747865742E68h        ; ".text\0\0\0"
    mov     qword ptr [rdi], rax
    mov     dword ptr [rdi + 8], 1000h  ; VirtualSize
    mov     dword ptr [rdi + 12], 1000h ; VirtualAddress
    mov     dword ptr [rdi + 16], 200h  ; SizeOfRawData
    mov     dword ptr [rdi + 20], 400h  ; PointerToRawData
    mov     dword ptr [rdi + 36], 60000020h ; Characteristics = CODE | EXECUTE | READ
    add     rdi, 40

    ; .data
    mov     rax, 00617461642E68h        ; ".data\0\0\0"
    mov     qword ptr [rdi], rax
    mov     dword ptr [rdi + 8], 1000h  ; VirtualSize
    mov     dword ptr [rdi + 12], 2000h ; VirtualAddress
    mov     dword ptr [rdi + 16], 200h  ; SizeOfRawData
    mov     dword ptr [rdi + 20], 600h  ; PointerToRawData
    mov     dword ptr [rdi + 36], 0C0000040h ; Characteristics = DATA | READ | WRITE
    add     rdi, 40

    ; .rdata
    mov     rax, 0061746164722E68h      ; ".rdata\0\0"
    mov     qword ptr [rdi], rax
    mov     dword ptr [rdi + 8], 1000h  ; VirtualSize
    mov     dword ptr [rdi + 12], 3000h ; VirtualAddress
    mov     dword ptr [rdi + 16], 200h  ; SizeOfRawData
    mov     dword ptr [rdi + 20], 800h  ; PointerToRawData
    mov     dword ptr [rdi + 36], 40000040h ; Characteristics = READ | INITIALIZED_DATA
    add     rdi, 40

    ; Finalization: Calculate total bytes written
    sub     rdi, [rsp]                  ; Original RCX (DestBuf)
    mov     rax, rdi
    pop     rdi
    ret
XR_Emit_PE_Header ENDP

; -----------------------------------------------------------------------------------------
; XR_Seal_Runtime_Artifact
; Inputs:  RCX = Base of Sealed Graph
;          RDX = Size of Graph Data
;          R8  = Target Filename (optional, for disk-caching)
; Outputs: RAX = Handle or Success Code
; -----------------------------------------------------------------------------------------
PUBLIC XR_Seal_Runtime_Artifact
XR_Seal_Runtime_Artifact PROC
    ; This routine coordinates:
    ; 1. Allocating a staging buffer
    ; 2. Calling XR_Emit_PE_Header
    ; 3. Mapping Section Data from the runtime graph
    ; 4. Writing to disk or re-mapping as an executable child process
    xor eax, eax
    ret
XR_Seal_Runtime_Artifact ENDP

END
