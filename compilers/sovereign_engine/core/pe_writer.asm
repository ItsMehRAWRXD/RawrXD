; ============================================================================
; Sovereign Compiler Engine - PE Writer
; Direct PE32+ binary emission without external linker
; ============================================================================

option casemap:none
option win64:3

; ============================================================================
; PE Constants
; ============================================================================
IMAGE_DOS_SIGNATURE           equ 5A4Dh
IMAGE_NT_SIGNATURE            equ 00004550h
IMAGE_FILE_MACHINE_AMD64      equ 8664h
IMAGE_FILE_EXECUTABLE_IMAGE   equ 0002h
IMAGE_FILE_LARGE_ADDRESS_AWARE equ 0020h

IMAGE_SUBSYSTEM_WINDOWS_CUI   equ 3
IMAGE_SUBSYSTEM_WINDOWS_GUI   equ 2

IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE equ 0040h
IMAGE_DLLCHARACTERISTICS_NX_COMPAT    equ 0100h
IMAGE_DLLCHARACTERISTICS_GUARD_CF     equ 4000h

SECTION_CODE                  equ 60000020h    ; CODE | EXECUTE | READ
SECTION_DATA                  equ 40000040h    ; INITIALIZED_DATA | READ
SECTION_BSS                   equ 40000080h    ; UNINITIALIZED_DATA | READ

; ============================================================================
; Data Structures
; ============================================================================

PE_BUILDER STRUCT
    ; DOS Header
    dos_header          BYTE 64 DUP(?)
    
    ; NT Headers
    nt_signature        DWORD ?
    file_header         BYTE 24 DUP(?)       ; IMAGE_FILE_HEADER
    optional_header     BYTE 240 DUP(?)      ; IMAGE_OPTIONAL_HEADER64
    
    ; Section Headers (max 16)
    section_headers     BYTE 16 * 40 DUP(?)  ; IMAGE_SECTION_HEADER[16]
    section_count       DWORD ?
    
    ; Section Data
    text_section        QWORD ?              ; Code
    data_section        QWORD ?              ; Initialized data
    bss_section         QWORD ?              ; Uninitialized data
    
    ; Output
    output_buffer       QWORD ?
    output_size         QWORD ?
    current_offset      QWORD ?
PE_BUILDER ENDS

; ============================================================================
; Global Data
; ============================================================================
.data
    pe_builder          PE_BUILDER <>
    
    ; Standard section names
    section_text_name   BYTE ".text", 0, 0, 0
    section_data_name   BYTE ".data", 0, 0, 0
    section_bss_name    BYTE ".bss", 0, 0, 0, 0

; ============================================================================
; Code
; ============================================================================
.code

; ----------------------------------------------------------------------------
; Initialize PE Builder
; ----------------------------------------------------------------------------
pe_init PROC
    push rbp
    mov rbp, rsp
    
    ; Clear builder
    lea rdi, pe_builder
    mov rcx, SIZEOF PE_BUILDER
    xor eax, eax
    rep stosb
    
    ; Allocate output buffer (1MB)
    mov ecx, 1048576
    mov edx, 3000h              ; MEM_COMMIT | MEM_RESERVE
    mov r8d, 4                  ; PAGE_READWRITE
    xor r9d, r9d
    call VirtualAlloc
    mov pe_builder.output_buffer, rax
    mov pe_builder.current_offset, 0
    
    ; Build DOS header
    call pe_build_dos_header
    
    ; Build NT headers
    call pe_build_nt_headers
    
    mov rax, 1
    leave
    ret
pe_init ENDP

; ----------------------------------------------------------------------------
; Build DOS Header
; ----------------------------------------------------------------------------
pe_build_dos_header PROC
    push rbp
    mov rbp, rsp
    
    mov rdi, pe_builder.output_buffer
    
    ; e_magic
    mov word ptr [rdi], IMAGE_DOS_SIGNATURE
    
    ; e_cblp, e_cp, e_crlc, e_cparhdr
    mov word ptr [rdi+2], 90h
    mov word ptr [rdi+4], 3
    mov word ptr [rdi+6], 0
    mov word ptr [rdi+8], 4
    
    ; e_minalloc, e_maxalloc
    mov word ptr [rdi+10], 0
    mov word ptr [rdi+12], 0FFFFh
    
    ; e_ss, e_sp, e_csum, e_ip, e_cs
    mov word ptr [rdi+14], 0
    mov word ptr [rdi+16], 0B8h
    mov word ptr [rdi+18], 0
    mov word ptr [rdi+20], 0
    mov word ptr [rdi+22], 0
    
    ; e_lfarlc, e_ovno
    mov word ptr [rdi+24], 40h
    mov word ptr [rdi+26], 0
    
    ; e_res (4 words)
    mov dword ptr [rdi+28], 0
    mov dword ptr [rdi+32], 0
    
    ; e_oemid, e_oeminfo
    mov word ptr [rdi+36], 0
    mov word ptr [rdi+38], 0
    
    ; e_res2 (10 words)
    mov rcx, 10
    lea rdi, [rdi+40]
    xor eax, eax
    rep stosw
    
    ; e_lfanew (offset to PE header)
    mov rdi, pe_builder.output_buffer
    mov dword ptr [rdi+60], 64
    
    ; DOS stub program
    lea rdi, [rdi+64]
    mov byte ptr [rdi-64+64], 0Eh      ; push cs
    mov byte ptr [rdi-64+65], 1Fh      ; pop ds
    mov byte ptr [rdi-64+66], 0BAh     ; mov dx, offset message
    mov byte ptr [rdi-64+67], 0Eh
    mov byte ptr [rdi-64+68], 0
    mov byte ptr [rdi-64+69], 0B4h     ; mov ah, 9
    mov byte ptr [rdi-64+70], 09h
    mov byte ptr [rdi-64+71], 0CDh     ; int 21h
    mov byte ptr [rdi-64+72], 21h
    mov byte ptr [rdi-64+73], 0B8h     ; mov ax, 4C01h
    mov byte ptr [rdi-64+74], 01h
    mov byte ptr [rdi-64+75], 4Ch
    mov byte ptr [rdi-64+76], 0CDh     ; int 21h
    mov byte ptr [rdi-64+77], 21h
    
    ; DOS message
    lea rdi, [rdi+78]
    mov rsi, offset dos_message
    mov rcx, dos_message_len
    rep movsb
    
    mov pe_builder.current_offset, 128
    
    leave
    ret
    
dos_message db "This program requires Win64", 13, 10, "$"
dos_message_len equ $ - dos_message
pe_build_dos_header ENDP

; ----------------------------------------------------------------------------
; Build NT Headers
; ----------------------------------------------------------------------------
pe_build_nt_headers PROC
    push rbp
    mov rbp, rsp
    
    mov rdi, pe_builder.output_buffer
    add rdi, 128                    ; After DOS header
    
    ; PE Signature
    mov dword ptr [rdi], IMAGE_NT_SIGNATURE
    add rdi, 4
    
    ; File Header
    mov word ptr [rdi], IMAGE_FILE_MACHINE_AMD64    ; Machine
    mov word ptr [rdi+2], 3                          ; NumberOfSections
    mov dword ptr [rdi+4], 0                         ; TimeDateStamp
    mov dword ptr [rdi+8], 0                         ; PointerToSymbolTable
    mov dword ptr [rdi+12], 0                        ; NumberOfSymbols
    mov word ptr [rdi+16], 240                       ; SizeOfOptionalHeader
    mov word ptr [rdi+18], 0022h                     ; Characteristics
    add rdi, 24
    
    ; Optional Header (PE32+)
    mov word ptr [rdi], 020Bh                        ; Magic (PE32+)
    mov byte ptr [rdi+2], 1                          ; MajorLinkerVersion
    mov byte ptr [rdi+3], 0                          ; MinorLinkerVersion
    mov dword ptr [rdi+4], 0                         ; SizeOfCode
    mov dword ptr [rdi+8], 0                         ; SizeOfInitializedData
    mov dword ptr [rdi+12], 0                        ; SizeOfUninitializedData
    mov dword ptr [rdi+16], 1000h                    ; AddressOfEntryPoint
    mov dword ptr [rdi+20], 1000h                    ; BaseOfCode
    mov qword ptr [rdi+24], 140000000h               ; ImageBase
    mov dword ptr [rdi+32], 1000h                    ; SectionAlignment
    mov dword ptr [rdi+36], 200h                     ; FileAlignment
    mov word ptr [rdi+40], 6                         ; MajorOSVersion
    mov word ptr [rdi+42], 0                         ; MinorOSVersion
    mov word ptr [rdi+44], 0                         ; MajorImageVersion
    mov word ptr [rdi+46], 0                         ; MinorImageVersion
    mov word ptr [rdi+48], 6                         ; MajorSubsystemVersion
    mov word ptr [rdi+50], 0                         ; MinorSubsystemVersion
    mov dword ptr [rdi+52], 0                        ; Win32VersionValue
    mov dword ptr [rdi+56], 0                        ; SizeOfImage (calculated later)
    mov dword ptr [rdi+60], 400h                     ; SizeOfHeaders
    mov dword ptr [rdi+64], 0                        ; CheckSum
    mov word ptr [rdi+68], IMAGE_SUBSYSTEM_WINDOWS_CUI  ; Subsystem
    mov word ptr [rdi+70], 0140h                     ; DllCharacteristics
    mov qword ptr [rdi+72], 100000h                  ; SizeOfStackReserve
    mov qword ptr [rdi+80], 1000h                    ; SizeOfStackCommit
    mov qword ptr [rdi+88], 100000h                  ; SizeOfHeapReserve
    mov qword ptr [rdi+96], 1000h                    ; SizeOfHeapCommit
    mov dword ptr [rdi+104], 0                       ; LoaderFlags
    mov dword ptr [rdi+108], 16                      ; NumberOfRvaAndSizes
    
    ; Data directories (16 entries, 8 bytes each)
    add rdi, 112
    mov rcx, 16
    xor rax, rax
    rep stosq
    
    mov pe_builder.current_offset, 400
    
    leave
    ret
pe_build_nt_headers ENDP

; ----------------------------------------------------------------------------
; Add Section
; ----------------------------------------------------------------------------
pe_add_section PROC
    ; rcx = name, rdx = size, r8 = characteristics
    push rbp
    mov rbp, rsp
    push rsi
    push rdi
    
    mov rsi, rcx
    
    ; Get section header slot
    mov eax, pe_builder.section_count
    cmp eax, 16
    jae section_overflow
    
    ; Calculate section header address
    mov rdi, pe_builder.output_buffer
    add rdi, 400                    ; After headers
    mov rbx, 40
    mul ebx
    add rdi, rax
    
    ; Copy section name (8 bytes max)
    mov rcx, 8
    rep movsb
    
    ; Fill section header
    mov [rdi-8+8], edx              ; VirtualSize
    mov eax, pe_builder.section_count
    inc eax
    shl eax, 12                     ; * 4096 (section alignment)
    add eax, 1000h                  ; Base RVA
    mov [rdi-8+12], eax             ; VirtualAddress
    
    ; Align size to file alignment
    mov eax, edx
    add eax, 511
    and eax, not 511
    mov [rdi-8+16], eax             ; SizeOfRawData
    
    mov eax, pe_builder.current_offset
    mov [rdi-8+20], eax             ; PointerToRawData
    mov dword ptr [rdi-8+24], 0     ; PointerToRelocations
    mov dword ptr [rdi-8+28], 0     ; PointerToLinenumbers
    mov word ptr [rdi-8+32], 0      ; NumberOfRelocations
    mov word ptr [rdi-8+34], 0      ; NumberOfLinenumbers
    mov [rdi-8+36], r8d             ; Characteristics
    
    ; Update builder state
    inc pe_builder.section_count
    
    ; Advance current offset
    mov eax, [rdi-8+16]
    add pe_builder.current_offset, rax
    
    mov rax, 1
    jmp section_done
    
section_overflow:
    xor rax, rax
    
section_done:
    pop rdi
    pop rsi
    leave
    ret
pe_add_section ENDP

; ----------------------------------------------------------------------------
; Finalize and Write PE
; ----------------------------------------------------------------------------
pe_finalize PROC
    push rbp
    mov rbp, rsp
    
    ; Calculate final image size
    mov eax, pe_builder.section_count
    inc eax
    shl eax, 12                     ; (sections + 1) * 4096
    add eax, 1000h                  ; Headers
    
    ; Update SizeOfImage in optional header
    mov rdi, pe_builder.output_buffer
    add rdi, 128 + 4 + 24 + 56      ; DOS + sig + file header + offset
    mov [rdi], eax
    
    ; Return output buffer and size
    mov rax, pe_builder.output_buffer
    mov rdx, pe_builder.current_offset
    
    leave
    ret
pe_finalize ENDP

END
