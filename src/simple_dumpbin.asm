<<<<<<< HEAD
; ============================================================================
; MONOLITHIC x64 STANDALONE DUMPBIN
; 100% Pure MASM x64 - Zero External Dependencies (No .lib / .inc headers)
; Deep PE32+ Structure Analysis & Minimal Syscall-style API usage
; Optimized for Backend Development & Reverse Engineering
; ============================================================================

.code

; ============================================================================
; External Windows API declarations
; ============================================================================
EXTERN GetStdHandle    : PROC
EXTERN WriteConsoleA   : PROC
EXTERN ReadConsoleA    : PROC
EXTERN CreateFileA     : PROC
EXTERN ReadFile        : PROC
EXTERN CloseHandle     : PROC
EXTERN GetFileSizeEx   : PROC
EXTERN GetProcessHeap  : PROC
EXTERN HeapAlloc       : PROC
EXTERN HeapFree        : PROC
EXTERN ExitProcess     : PROC

; ============================================================================
; Constants
; ============================================================================
STD_INPUT_HANDLE        equ -10
STD_OUTPUT_HANDLE       equ -11
GENERIC_READ            equ 80000000h
FILE_SHARE_READ         equ 1
OPEN_EXISTING           equ 3
FILE_ATTRIBUTE_NORMAL   equ 80h
INVALID_HANDLE_VALUE    equ -1
HEAP_ZERO_MEMORY        equ 8

PE_SIGNATURE            equ 00004550h  ; "PE\0\0"
MZ_SIGNATURE            equ 5A4Dh      ; "MZ"

; ============================================================================
; Structures (Manual definitions for zero-dep)
; ============================================================================

IMAGE_DOS_HEADER STRUCT
    e_magic    WORD ?
    e_cblp     WORD ?
    e_cp       WORD ?
    e_crlc     WORD ?
    e_cparhdr  WORD ?
    e_minalloc WORD ?
    e_maxalloc WORD ?
    e_ss       WORD ?
    e_sp       WORD ?
    e_csum     WORD ?
    e_ip       WORD ?
    e_cs       WORD ?
    e_lfarlc   WORD ?
    e_ovno     WORD ?
    e_res      WORD 4 dup(?)
    e_oemid    WORD ?
    e_oeminfo  WORD ?
    e_res2     WORD 10 dup(?)
    e_lfanew   DWORD ?
IMAGE_DOS_HEADER ENDS

IMAGE_FILE_HEADER STRUCT
    Machine              WORD ?
    NumberOfSections     WORD ?
    TimeDateStamp        DWORD ?
    PointerToSymbolTable DWORD ?
    NumberOfSymbols      DWORD ?
    SizeOfOptionalHeader WORD ?
    Characteristics      WORD ?
IMAGE_FILE_HEADER ENDS

IMAGE_DATA_DIRECTORY STRUCT
    VirtualAddress DWORD ?
    Size           DWORD ?
IMAGE_DATA_DIRECTORY ENDS

IMAGE_OPTIONAL_HEADER64 STRUCT
    Magic                       WORD ?
    MajorLinkerVersion          BYTE ?
    MinorLinkerVersion          BYTE ?
    SizeOfCode                  DWORD ?
    SizeOfInitializedData       DWORD ?
    SizeOfUninitializedData     DWORD ?
    AddressOfEntryPoint         DWORD ?
    BaseOfCode                  DWORD ?
    ImageBase                   QWORD ?
    SectionAlignment            DWORD ?
    FileAlignment               DWORD ?
    MajorOperatingSystemVersion WORD ?
    MinorOperatingSystemVersion WORD ?
    MajorImageVersion           WORD ?
    MinorImageVersion           WORD ?
    MajorSubsystemVersion       WORD ?
    MinorSubsystemVersion       WORD ?
    Win32VersionValue           DWORD ?
    SizeOfImage                 DWORD ?
    SizeOfHeaders               DWORD ?
    CheckSum                    DWORD ?
    Subsystem                   WORD ?
    DllCharacteristics          WORD ?
    SizeOfStackReserve          QWORD ?
    SizeOfStackCommit           QWORD ?
    SizeOfHeapReserve           QWORD ?
    SizeOfHeapCommit            QWORD ?
    LoaderFlags                 DWORD ?
    NumberOfRvaAndSizes         DWORD ?
    DataDirectory               IMAGE_DATA_DIRECTORY 16 dup(<>)
IMAGE_OPTIONAL_HEADER64 ENDS

IMAGE_NT_HEADERS64 STRUCT
    Signature      DWORD ?
    FileHeader     IMAGE_FILE_HEADER <>
    OptionalHeader IMAGE_OPTIONAL_HEADER64 <>
IMAGE_NT_HEADERS64 ENDS

IMAGE_SECTION_HEADER STRUCT
    Name1                   BYTE 8 dup(?)
    Union_PhysicalAddress   DWORD ? ; or VirtualSize
    VirtualAddress          DWORD ?
    SizeOfRawData           DWORD ?
    PointerToRawData        DWORD ?
    PointerToRelocations    DWORD ?
    PointerToLinenumbers    DWORD ?
    NumberOfRelocations     WORD ?
    NumberOfLinenumbers     WORD ?
    Characteristics         DWORD ?
IMAGE_SECTION_HEADER ENDS

IMAGE_IMPORT_DESCRIPTOR STRUCT
    OriginalFirstThunk    DWORD ?
    TimeDateStamp         DWORD ?
    ForwarderChain        DWORD ?
    Name1                 DWORD ?
    FirstThunk            DWORD ?
IMAGE_IMPORT_DESCRIPTOR ENDS

; ============================================================================
; Data Section
; ============================================================================
.data
    ; UI Strings
    msg_header      db "=== MONOLITHIC x64 PE DUMPBIN ===", 13, 10, 0
    msg_prompt      db "Enter PE file path: ", 0
    msg_error_open  db "[-] Error: Could not open file.", 13, 10, 0
    msg_error_size  db "[-] Error: Could not get file size.", 13, 10, 0
    msg_error_read  db "[-] Error: Could not read file.", 13, 10, 0
    msg_error_pe    db "[-] Error: Not a valid PE64 file.", 13, 10, 0
    
    ; Info labels
    lbl_magic       db "[+] DOS Magic:          0x", 0
    lbl_lfanew      db "[+] PE Offset:          0x", 0
    lbl_signature   db "[+] NT Signature:       0x", 0
    lbl_sections    db "[+] Number of Sections: ", 0
    lbl_entry       db "[+] Entry Point RVA:    0x", 0
    lbl_imagebase   db "[+] Image Base:         0x", 0
    lbl_section_hdr db 13, 10, "--- SECTION TABLE ---", 13, 10, 0
    lbl_import_hdr  db 13, 10, "--- IMPORT TABLE ---", 13, 10, 0
    
    msg_newline     db 13, 10, 0
    msg_space       db "  ", 0
    msg_slash       db " / ", 0
    
    hex_chars       db "0123456789ABCDEF"

.data?
    stdin_h         dq ?
    stdout_h        dq ?
    file_h          dq ?
    file_size       dq ?
    file_buffer     dq ?
    p_nt_header     dq ?
    p_sections      dq ?
    num_sections    dw ?
    bytes_rw        dd ?
    input_buffer    db 260 dup(?)
    hex_buffer      db 20 dup(?)

; ============================================================================
; Main Entry
; ============================================================================
main PROC
    sub     rsp, 40

    ; Get Handles
    mov     rcx, STD_INPUT_HANDLE
    call    GetStdHandle
    mov     [stdin_h], rax
    
    mov     rcx, STD_OUTPUT_HANDLE
    call    GetStdHandle
    mov     [stdout_h], rax
    
    ; Print Header
    lea     rcx, msg_header
    call    print_string
    
    ; Prompt for File
    lea     rcx, msg_prompt
    call    print_string
    
    ; Read Input
    mov     rcx, [stdin_h]
    lea     rdx, input_buffer
    mov     r8, 255
    lea     r9, bytes_rw
    mov     qword ptr [rsp+32], 0
    call    ReadConsoleA
    
    ; Trim input
    xor     rax, rax
    mov     eax, [bytes_rw]
    cmp     eax, 2
    jb      err_open
    lea     rdx, input_buffer
    add     rdx, rax
@@trim:
    dec     rdx
    cmp     byte ptr [rdx], 13
    je      @@zero
    cmp     byte ptr [rdx], 10
    je      @@zero
    jmp     @@done_trim
@@zero:
    mov     byte ptr [rdx], 0
    jmp     @@trim
@@done_trim:

    ; Open File
    lea     rcx, input_buffer
    mov     rdx, GENERIC_READ
    mov     r8, FILE_SHARE_READ
    xor     r9, r9
    mov     qword ptr [rsp+32], OPEN_EXISTING
    mov     qword ptr [rsp+40], FILE_ATTRIBUTE_NORMAL
    mov     qword ptr [rsp+48], 0
    call    CreateFileA
    cmp     rax, INVALID_HANDLE_VALUE
    je      err_open
    mov     [file_h], rax
    
    ; Get File Size
    mov     rcx, [file_h]
    lea     rdx, file_size
    call    GetFileSizeEx
    test    rax, rax
    jz      err_size
    
    ; Allocate Memory
    call    GetProcessHeap
    mov     rcx, rax
    mov     rdx, HEAP_ZERO_MEMORY
    mov     r8, [file_size]
    call    HeapAlloc
    test    rax, rax
    jz      err_read
    mov     [file_buffer], rax
    
    ; Read File
    mov     rcx, [file_h]
    mov     rdx, [file_buffer]
    mov     r8, [file_size]
    lea     r9, bytes_rw
    mov     qword ptr [rsp+32], 0
    call    ReadFile
    test    rax, rax
    jz      err_read
    
    call    CloseHandle
    
    ; --- Analysis ---
    mov     rbx, [file_buffer]
    
    ; Validate DOS Header
    cmp     word ptr [rbx], MZ_SIGNATURE
    jne     err_pe
    
    ; Print DOS Info
    lea     rcx, lbl_magic
    call    print_string
    movzx   rcx, word ptr [rbx]
    call    print_hex16
    call    print_newline
    
    mov     eax, (IMAGE_DOS_HEADER ptr [rbx]).e_lfanew
    lea     rcx, lbl_lfanew
    call    print_string
    mov     ecx, eax
    call    print_hex32
    call    print_newline
    
    ; Validate PE Header
    mov     rbx, [file_buffer]
    add     rbx, rax                ; rbx points to IMAGE_NT_HEADERS64
    mov     [p_nt_header], rbx
    
    cmp     (IMAGE_NT_HEADERS64 ptr [rbx]).Signature, PE_SIGNATURE
    jne     err_pe
    
    lea     rcx, lbl_signature
    call    print_string
    mov     ecx, (IMAGE_NT_HEADERS64 ptr [rbx]).Signature
    call    print_hex32
    call    print_newline
    
    ; Machine / Sections
    lea     rcx, lbl_sections
    call    print_string
    movzx   rcx, (IMAGE_NT_HEADERS64 ptr [rbx]).FileHeader.NumberOfSections
    mov     [num_sections], cx
    call    print_dec
    call    print_newline
    
    ; Optional Header
    lea     rcx, lbl_entry
    call    print_string
    mov     ecx, (IMAGE_NT_HEADERS64 ptr [rbx]).OptionalHeader.AddressOfEntryPoint
    call    print_hex32
    call    print_newline
    
    lea     rcx, lbl_imagebase
    call    print_string
    mov     rcx, (IMAGE_NT_HEADERS64 ptr [rbx]).OptionalHeader.ImageBase
    call    print_hex64
    call    print_newline
    
    ; --- Sections ---
    lea     rcx, lbl_section_hdr
    call    print_string
    
    movzx   r12d, [num_sections]
    movzx   eax, (IMAGE_NT_HEADERS64 ptr [rbx]).FileHeader.SizeOfOptionalHeader
    lea     rsi, (IMAGE_NT_HEADERS64 ptr [rbx]).OptionalHeader
    add     rsi, rax                ; rsi points to first section header
    mov     [p_sections], rsi
    
sect_loop:
    test    r12d, r12d
    jz      do_imports
    
    lea     rcx, [rsi]
    call    print_string_n
    lea     rcx, msg_space
    call    print_string
    mov     ecx, (IMAGE_SECTION_HEADER ptr [rsi]).VirtualAddress
    call    print_hex32
    lea     rcx, msg_slash
    call    print_string
    mov     ecx, (IMAGE_SECTION_HEADER ptr [rsi]).SizeOfRawData
    call    print_hex32
    call    print_newline
    
    add     rsi, TYPE IMAGE_SECTION_HEADER
    dec     r12d
    jmp     sect_loop

do_imports:
    mov     rbx, [p_nt_header]
    mov     eax, (IMAGE_NT_HEADERS64 ptr [rbx]).OptionalHeader.DataDirectory[1*8].VirtualAddress
    test    eax, eax
    jz      done
    
    lea     rcx, lbl_import_hdr
    call    print_string
    
    mov     ecx, eax
    call    RvaToOffset
    test    rax, rax
    jz      done
    
    add     rax, [file_buffer]
    mov     rsi, rax

imp_loop:
    mov     eax, (IMAGE_IMPORT_DESCRIPTOR ptr [rsi]).Name1
    test    eax, eax
    jz      done
    
    mov     ecx, eax
    call    RvaToOffset
    add     rax, [file_buffer]
    mov     rcx, rax
    call    print_string
    call    print_newline
    
    add     rsi, TYPE IMAGE_IMPORT_DESCRIPTOR
    jmp     imp_loop

done:
    xor     rcx, rcx
    call    ExitProcess

err_open:
    lea     rcx, msg_error_open
    call    print_string
    jmp     done

err_size:
    lea     rcx, msg_error_size
    call    print_string
    jmp     done

err_read:
    lea     rcx, msg_error_read
    call    print_string
    jmp     done

err_pe:
    lea     rcx, msg_error_pe
    call    print_string
    jmp     done

main ENDP

; ============================================================================
; Utility Functions
; ============================================================================

RvaToOffset PROC
    ; ecx = RVA
    ; returns offset in rax
    push    rbx
    push    rsi
    push    rdi
    
    movzx   r8d, [num_sections]
    mov     rsi, [p_sections]
    
@@loop:
    test    r8d, r8d
    jz      @@none
    
    mov     eax, (IMAGE_SECTION_HEADER ptr [rsi]).VirtualAddress
    mov     edx, eax
    add     edx, (IMAGE_SECTION_HEADER ptr [rsi]).Union_PhysicalAddress ; VirtualSize
    
    cmp     ecx, eax
    jb      @@next
    cmp     ecx, edx
    jae     @@next
    
    ; Found it
    sub     ecx, eax
    add     ecx, (IMAGE_SECTION_HEADER ptr [rsi]).PointerToRawData
    mov     eax, ecx
    jmp     @@ret
    
@@next:
    add     rsi, TYPE IMAGE_SECTION_HEADER
    dec     r8d
    jmp     @@loop
    
@@none:
    xor     rax, rax
@@ret:
    pop     rdi
    pop     rsi
    pop     rbx
    ret
RvaToOffset ENDP

print_string PROC
    test    rcx, rcx
    jz      @@ret
    push    rsi
    push    rdi
    sub     rsp, 32
    mov     rsi, rcx
    xor     rdi, rdi
@@len:
    cmp     byte ptr [rsi+rdi], 0
    je      @@found
    inc     rdi
    jmp     @@len
@@found:
    mov     rcx, [stdout_h]
    mov     rdx, rsi
    mov     r8, rdi
    lea     r9, bytes_rw
    mov     qword ptr [rsp+32], 0
    call    WriteConsoleA
    add     rsp, 32
    pop     rdi
    pop     rsi
@@ret:
    ret
print_string ENDP

print_string_n PROC
    push    rsi
    push    rdi
    sub     rsp, 32
    mov     rsi, rcx
    xor     rdi, rdi
@@len:
    cmp     rdi, 8
    je      @@found
    cmp     byte ptr [rsi+rdi], 0
    je      @@found
    inc     rdi
    jmp     @@len
@@found:
    mov     rcx, [stdout_h]
    mov     rdx, rsi
    mov     r8, rdi
    lea     r9, bytes_rw
    mov     qword ptr [rsp+32], 0
    call    WriteConsoleA
    add     rsp, 32
    pop     rdi
    pop     rsi
    ret
print_string_n ENDP

print_newline PROC
    lea     rcx, msg_newline
    jmp     print_string
print_newline ENDP

print_hex64 PROC
    sub     rsp, 40
    mov     r10, rcx
    mov     r11, 16
@@loop:
    rol     r10, 4
    mov     rax, r10
    and     rax, 0Fh
    lea     rdx, hex_chars
    movzx   eax, byte ptr [rdx+rax]
    mov     byte ptr [hex_buffer], al
    mov     rcx, [stdout_h]
    lea     rdx, hex_buffer
    mov     r8, 1
    lea     r9, bytes_rw
    mov     qword ptr [rsp+32], 0
    call    WriteConsoleA
    dec     r11
    jnz     @@loop
    add     rsp, 40
    ret
print_hex64 ENDP

print_hex32 PROC
    sub     rsp, 40
    mov     r10d, ecx
    mov     r11, 8
@@loop:
    rol     r10d, 4
    mov     eax, r10d
    and     eax, 0Fh
    lea     rdx, hex_chars
    movzx   eax, byte ptr [rdx+rax]
    mov     byte ptr [hex_buffer], al
    mov     rcx, [stdout_h]
    lea     rdx, hex_buffer
    mov     r8, 1
    lea     r9, bytes_rw
    mov     qword ptr [rsp+32], 0
    call    WriteConsoleA
    dec     r11
    jnz     @@loop
    add     rsp, 40
    ret
print_hex32 ENDP

print_hex16 PROC
    sub     rsp, 40
    mov     r10w, cx
    mov     r11, 4
@@loop:
    rol     r10w, 4
    movzx   eax, r10w
    and     eax, 0Fh
    lea     rdx, hex_chars
    movzx   eax, byte ptr [rdx+rax]
    mov     byte ptr [hex_buffer], al
    mov     rcx, [stdout_h]
    lea     rdx, hex_buffer
    mov     r8, 1
    lea     r9, bytes_rw
    mov     qword ptr [rsp+32], 0
    call    WriteConsoleA
    dec     r11
    jnz     @@loop
    add     rsp, 40
    ret
print_hex16 ENDP

print_dec PROC
    sub     rsp, 56
    mov     rax, rcx
    lea     rdi, [hex_buffer + 19]
    mov     byte ptr [rdi], 0
    mov     rbx, 10
@@loop:
    xor     rdx, rdx
    div     rbx
    add     dl, '0'
    dec     rdi
    mov     [rdi], dl
    test    rax, rax
    jnz     @@loop
    mov     rcx, rdi
    call    print_string
    add     rsp, 56
    ret
print_dec ENDP

END
=======
;============================================================================
; Simple DumpBin Replacement v6.0
; Basic file analysis tool
;============================================================================

.386
.model flat, stdcall
option casemap :none

;============================================================================
; INCLUDES
;============================================================================

include windows.inc
include kernel32.inc
include user32.inc

includelib kernel32.lib
includelib user32.lib

;============================================================================
; CONSTANTS
;============================================================================

CLI_VERSION             equ "6.0.0"
MAX_PATH                equ 260
MAX_FILE_SIZE           equ 10485760   ; 10MB limit
PE_SIGNATURE            equ 00004550h  ; "PE\0\0"
MZ_SIGNATURE            equ 00005A4Dh  ; "MZ"

;============================================================================
; DATA
;============================================================================

.data

szWelcome               db "DumpBin Replacement v", CLI_VERSION, 0Dh, 0Ah
                        db "========================================", 0Dh, 0Ah, 0Dh, 0Ah, 0
szMenu                  db "[1] Load file", 0Dh, 0Ah
                        db "[2] Hex dump", 0Dh, 0Ah
                        db "[3] Show PE header", 0Dh, 0Ah
                        db "[4] Exit", 0Dh, 0Ah
                        db "Select option: ", 0
szPromptFile            db "Enter file path: ", 0
szPromptAddress         db "Enter start offset (hex): ", 0
szPromptSize            db "Enter size: ", 0
szFileLoaded            db "[+] File loaded successfully. Size: ", 0
szPEHeader              db 0Dh, 0Ah, "PE Header Found:", 0Dh, 0Ah, 0
szNoPE                  db "[-] No PE header found.", 0Dh, 0Ah, 0
szHexDumpHeader         db 0Dh, 0Ah, "Hex Dump:", 0Dh, 0Ah
                        db "========================================", 0Dh, 0Ah, 0
szError                 db "[-] ERROR: ", 0
szErrorFileOpen         db "Failed to open file.", 0Dh, 0Ah, 0
szErrorFileRead         db "Failed to read file.", 0Dh, 0Ah, 0
szErrorInvalidFile      db "Invalid file.", 0Dh, 0Ah, 0
szErrorInvalidSize      db "File too large.", 0Dh, 0Ah, 0
szErrorInvalidAddress   db "Invalid address.", 0Dh, 0Ah, 0
szPressAnyKey           db 0Dh, 0Ah, "Press any key to continue...", 0
szNewLine               db 0Dh, 0Ah, 0
szFormatHex             db "%08X ", 0
szFormatDec             db "%d", 0
szFormatByte            db "%02X ", 0
szFormatAscii           db "%c", 0
szBuffer                db MAX_PATH dup(0)
szFilePath              db MAX_PATH dup(0)
fileBuffer              db MAX_FILE_SIZE dup(0)
hStdIn                  dd 0
hStdOut                 dd 0
hFile                   dd 0
dwFileSize              dd 0
dwBytesRead             dd 0

;============================================================================
; CODE
;============================================================================

.code

;----------------------------------------------------------------------------
; Display message
;----------------------------------------------------------------------------
DisplayMessage PROC lpMessage:DWORD
    LOCAL dwWritten :DWORD
    LOCAL dwLen :DWORD
    
    invoke lstrlen, lpMessage
    mov dwLen, eax
    
    invoke WriteConsole, hStdOut, lpMessage, dwLen, addr dwWritten, NULL
    
    ret
DisplayMessage ENDP

;----------------------------------------------------------------------------
; Read string input
;----------------------------------------------------------------------------
ReadString PROC
    LOCAL dwRead :DWORD
    
    invoke ReadConsole, hStdIn, addr szBuffer, 256, addr dwRead, NULL
    
    ; Remove newline
    mov eax, dwRead
    dec eax
    mov byte ptr [szBuffer+eax], 0
    
    ret
ReadString ENDP

;----------------------------------------------------------------------------
; Read integer input
;----------------------------------------------------------------------------
ReadInt PROC
    LOCAL dwRead :DWORD
    
    invoke ReadConsole, hStdIn, addr szBuffer, 256, addr dwRead, NULL
    
    ; Convert string to integer
    mov eax, 0
    lea esi, szBuffer
    
@@convert_loop:
    movzx ecx, byte ptr [esi]
    cmp ecx, 0Dh
    je @@done
    cmp ecx, 0
    je @@done
    
    sub ecx, '0'
    cmp ecx, 9
    ja @@invalid
    
    imul eax, eax, 10
    add eax, ecx
    inc esi
    jmp @@convert_loop
    
@@invalid:
    mov eax, -1
    
@@done:
    ret
ReadInt ENDP

;----------------------------------------------------------------------------
; Read hex input
;----------------------------------------------------------------------------
ReadHex PROC
    LOCAL dwRead :DWORD
    
    invoke ReadConsole, hStdIn, addr szBuffer, 256, addr dwRead, NULL
    
    ; Convert hex string to integer
    mov eax, 0
    lea esi, szBuffer
    
@@convert_loop:
    movzx ecx, byte ptr [esi]
    cmp ecx, 0Dh
    je @@done
    cmp ecx, 0
    je @@done
    
    ; Convert hex digit
    cmp ecx, '0'
    jb @@invalid
    cmp ecx, '9'
    jbe @@is_digit
    
    cmp ecx, 'A'
    jb @@invalid
    cmp ecx, 'F'
    jbe @@is_upper
    
    cmp ecx, 'a'
    jb @@invalid
    cmp ecx, 'f'
    ja @@invalid
    
    sub ecx, 'a'
    add ecx, 10
    jmp @@continue
    
@@is_upper:
    sub ecx, 'A'
    add ecx, 10
    jmp @@continue
    
@@is_digit:
    sub ecx, '0'
    
@@continue:
    shl eax, 4
    add eax, ecx
    inc esi
    jmp @@convert_loop
    
@@invalid:
    mov eax, 0
    
@@done:
    ret
ReadHex ENDP

;----------------------------------------------------------------------------
; Open and read file
;----------------------------------------------------------------------------
ReadInputFile PROC lpFilePath:DWORD
    LOCAL dwFileSizeHigh :DWORD
    
    ; Open file
    invoke CreateFile, lpFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
    cmp eax, INVALID_HANDLE_VALUE
    je @@error_open
    mov hFile, eax
    
    ; Get file size
    invoke GetFileSize, hFile, addr dwFileSizeHigh
    cmp eax, -1
    je @@error_size
    mov dwFileSize, eax
    
    ; Check if file is too large
    cmp eax, MAX_FILE_SIZE
    jg @@error_large
    
    ; Read file
    invoke ReadFile, hFile, addr fileBuffer, dwFileSize, addr dwBytesRead, NULL
    cmp eax, 0
    je @@error_read
    
    ; Close file
    invoke CloseHandle, hFile
    
    mov eax, TRUE
    ret
    
@@error_open:
    invoke DisplayMessage, addr szError
    invoke DisplayMessage, addr szErrorFileOpen
    mov eax, FALSE
    ret
    
@@error_size:
    invoke CloseHandle, hFile
    invoke DisplayMessage, addr szError
    invoke DisplayMessage, addr szErrorInvalidFile
    mov eax, FALSE
    ret
    
@@error_large:
    invoke CloseHandle, hFile
    invoke DisplayMessage, addr szError
    invoke DisplayMessage, addr szErrorInvalidSize
    mov eax, FALSE
    ret
    
@@error_read:
    invoke CloseHandle, hFile
    invoke DisplayMessage, addr szError
    invoke DisplayMessage, addr szErrorFileRead
    mov eax, FALSE
    ret
ReadInputFile ENDP

;----------------------------------------------------------------------------
; Detect PE file
;----------------------------------------------------------------------------
DetectPE PROC
    ; Check if file is large enough
    cmp dwFileSize, 64
    jl @@no_pe
    
    ; Check MZ signature
    mov ax, word ptr [fileBuffer]
    cmp ax, MZ_SIGNATURE
    jne @@no_pe
    
    ; Get PE offset
    mov eax, dword ptr [fileBuffer+60]  ; e_lfanew
    cmp eax, dwFileSize
    jge @@no_pe
    
    ; Check PE signature
    mov eax, dword ptr [fileBuffer+eax]
    cmp eax, PE_SIGNATURE
    jne @@no_pe
    
    mov eax, TRUE
    ret
    
@@no_pe:
    mov eax, FALSE
    ret
DetectPE ENDP

;----------------------------------------------------------------------------
; Show PE header info
;----------------------------------------------------------------------------
ShowPEHeader PROC
    LOCAL pPeHeader :DWORD
    LOCAL dwNumSections :DWORD
    
    ; Get PE offset
    mov eax, dword ptr [fileBuffer+60]  ; e_lfanew
    add eax, offset fileBuffer
    mov pPeHeader, eax
    
    ; Display header
    invoke DisplayMessage, addr szPEHeader
    
    ; Get number of sections
    movzx eax, word ptr [pPeHeader+6]  ; NumberOfSections
    mov dwNumSections, eax
    
    invoke DisplayMessage, addr szFormatDec
    invoke DisplayMessage, addr szNewLine
    
    mov eax, TRUE
    ret
ShowPEHeader ENDP

;----------------------------------------------------------------------------
; Hex dump
;----------------------------------------------------------------------------
HexDump PROC dwOffset:DWORD, dwSize:DWORD
    LOCAL i :DWORD
    LOCAL j :DWORD
    LOCAL bChar :BYTE
    
    ; Check bounds
    mov eax, dwOffset
    add eax, dwSize
    cmp eax, dwFileSize
    jg @@error_bounds
    
    ; Display header
    invoke DisplayMessage, addr szHexDumpHeader
    
    mov i, 0
    
@@dump_loop:
    cmp i, dwSize
    jge @@done
    
    ; Display offset
    mov eax, i
    add eax, dwOffset
    invoke wsprintf, addr szBuffer, addr szFormatHex, eax
    invoke DisplayMessage, addr szBuffer
    
    ; Display hex values
    mov j, 0
    
@@hex_loop:
    cmp j, 16
    jge @@ascii
    
    mov eax, i
    add eax, j
    cmp eax, dwSize
    jge @@ascii
    
    ; Get byte value
    movzx ecx, byte ptr [fileBuffer+eax+dwOffset]
    
    ; Format hex byte
    invoke wsprintf, addr szBuffer, addr szFormatByte, ecx
    invoke DisplayMessage, addr szBuffer
    
    inc j
    jmp @@hex_loop
    
@@ascii:
    ; Display ASCII
    invoke DisplayMessage, addr szHexBuffer
    mov j, 0
    
@@ascii_loop:
    cmp j, 16
    jge @@next_line
    
    mov eax, i
    add eax, j
    cmp eax, dwSize
    jge @@next_line
    
    ; Get byte value
    movzx ecx, byte ptr [fileBuffer+eax+dwOffset]
    
    ; Check if printable
    cmp cl, 20h
    jl @@non_printable
    cmp cl, 7Eh
    jg @@non_printable
    
    mov bChar, cl
    jmp @@print_char
    
@@non_printable:
    mov bChar, '.'
    
@@print_char:
    invoke wsprintf, addr szBuffer, addr szFormatAscii, bChar
    invoke DisplayMessage, addr szBuffer
    
    inc j
    jmp @@ascii_loop
    
@@next_line:
    invoke DisplayMessage, addr szNewLine
    
    add i, 16
    jmp @@dump_loop
    
@@done:
    mov eax, TRUE
    ret
    
@@error_bounds:
    invoke DisplayMessage, addr szError
    invoke DisplayMessage, addr szErrorInvalidAddress
    mov eax, FALSE
    ret
HexDump ENDP

;----------------------------------------------------------------------------
; Main menu
;----------------------------------------------------------------------------
MainMenu PROC
    LOCAL dwChoice :DWORD
    LOCAL dwOffset :DWORD
    LOCAL dwSize :DWORD
    
@@menu_loop:
    ; Display welcome
    invoke DisplayMessage, addr szWelcome
    
    ; Display menu
    invoke DisplayMessage, addr szMenu
    
    ; Get choice
    call ReadInt
    mov dwChoice, eax
    
    cmp dwChoice, 1
    je @@option_load
    
    cmp dwChoice, 2
    je @@option_hexdump
    
    cmp dwChoice, 3
    je @@option_peheader
    
    cmp dwChoice, 4
    je @@option_exit
    
    jmp @@menu_loop
    
@@option_load:
    invoke DisplayMessage, addr szPromptFile
    call ReadString
    
    ; Copy buffer to file path
    invoke lstrcpy, addr szFilePath, addr szBuffer
    
    call ReadInputFile, addr szFilePath
    cmp eax, FALSE
    je @@menu_loop
    
    invoke DisplayMessage, addr szFileLoaded
    invoke DisplayMessage, addr szFormatDec
    invoke DisplayMessage, addr szNewLine
    invoke DisplayMessage, addr szPressAnyKey
    call ReadString
    
    jmp @@menu_loop
    
@@option_hexdump:
    invoke DisplayMessage, addr szPromptAddress
    call ReadHex
    mov dwOffset, eax
    
    invoke DisplayMessage, addr szPromptSize
    call ReadInt
    mov dwSize, eax
    
    call HexDump, dwOffset, dwSize
    invoke DisplayMessage, addr szPressAnyKey
    call ReadString
    
    jmp @@menu_loop
    
@@option_peheader:
    call DetectPE
    cmp eax, FALSE
    je @@no_pe
    
    call ShowPEHeader
    jmp @@menu_loop
    
@@no_pe:
    invoke DisplayMessage, addr szNoPE
    invoke DisplayMessage, addr szPressAnyKey
    call ReadString
    jmp @@menu_loop
    
@@option_exit:
    mov eax, 0
    ret
    
MainMenu ENDP

;----------------------------------------------------------------------------
; Main entry point
;----------------------------------------------------------------------------
main PROC
    LOCAL dwExitCode :DWORD
    
    ; Get standard input/output handles
    invoke GetStdHandle, STD_INPUT_HANDLE
    mov hStdIn, eax
    
    invoke GetStdHandle, STD_OUTPUT_HANDLE
    mov hStdOut, eax
    
    ; Run main menu
    call MainMenu
    mov dwExitCode, eax
    
    ; Exit
    invoke ExitProcess, dwExitCode
main ENDP

END main
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
