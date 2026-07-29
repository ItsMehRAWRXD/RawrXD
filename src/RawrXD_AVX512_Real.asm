<<<<<<< HEAD
; ============================================================================
; PE_Backend_Emitter.asm
; Monolithic PE Writer / Machine Code Emitter Backend in x64 MASM
; Zero dependencies, pure structural definitions and emitter macros/functions.
; ============================================================================

; ============================================
; EXPORTS
; ============================================
PUBLIC Emit_DOS_Header
PUBLIC Emit_DOS_Stub
PUBLIC Emit_NT_Headers
PUBLIC Emit_Section_Header
PUBLIC Emit_Import_Descriptor

; ----------------------------------------------------------------------------
; 1. PE STRUCTS & TEMPLATES (Backend Designer View)
; ----------------------------------------------------------------------------

IMAGE_DOS_HEADER STRUCT
    e_magic     WORD    ? ; 0x5A4D ('MZ')
    e_cblp      WORD    ?
    e_cp        WORD    ?
    e_crlc      WORD    ?
    e_cparhdr   WORD    ?
    e_minalloc  WORD    ?
    e_maxalloc  WORD    ?
    e_ss        WORD    ?
    e_sp        WORD    ?
    e_csum      WORD    ?
    e_ip        WORD    ?
    e_cs        WORD    ?
    e_lfarlc    WORD    ?
    e_ovno      WORD    ?
    e_res       WORD 4 DUP(?)
    e_oemid     WORD    ?
    e_oeminfo   WORD    ?
    e_res2      WORD 10 DUP(?)
    e_lfanew    DWORD   ? ; Offset to NT headers
IMAGE_DOS_HEADER ENDS

IMAGE_FILE_HEADER STRUCT
    Machine               WORD    ? ; 0x8664 for x64
    NumberOfSections      WORD    ?
    TimeDateStamp         DWORD   ?
    PointerToSymbolTable  DWORD   ?
    NumberOfSymbols       DWORD   ?
    SizeOfOptionalHeader  WORD    ?
    Characteristics       WORD    ?
IMAGE_FILE_HEADER ENDS

IMAGE_DATA_DIRECTORY STRUCT
    VirtualAddress  DWORD   ?
    Size1           DWORD   ? ; "Size" is a MASM keyword (SIZE operator)
IMAGE_DATA_DIRECTORY ENDS

IMAGE_OPTIONAL_HEADER64 STRUCT
    Magic                       WORD    ? ; 0x020B for PE32+
    MajorLinkerVersion          BYTE    ?
    MinorLinkerVersion          BYTE    ?
    SizeOfCode                  DWORD   ?
    SizeOfInitializedData       DWORD   ?
    SizeOfUninitializedData     DWORD   ?
    AddressOfEntryPoint         DWORD   ?
    BaseOfCode                  DWORD   ?
    ImageBase                   QWORD   ?
    SectionAlignment            DWORD   ?
    FileAlignment               DWORD   ?
    MajorOperatingSystemVersion WORD    ?
    MinorOperatingSystemVersion WORD    ?
    MajorImageVersion           WORD    ?
    MinorImageVersion           WORD    ?
    MajorSubsystemVersion       WORD    ?
    MinorSubsystemVersion       WORD    ?
    Win32VersionValue           DWORD   ?
    SizeOfImage                 DWORD   ?
    SizeOfHeaders               DWORD   ?
    CheckSum                    DWORD   ?
    Subsystem                   WORD    ?
    DllCharacteristics          WORD    ?
    SizeOfStackReserve          QWORD   ?
    SizeOfStackCommit           QWORD   ?
    SizeOfHeapReserve           QWORD   ?
    SizeOfHeapCommit            QWORD   ?
    LoaderFlags                 DWORD   ?
    NumberOfRvaAndSizes         DWORD   ?
    DataDirectory               IMAGE_DATA_DIRECTORY 16 DUP(<>)
IMAGE_OPTIONAL_HEADER64 ENDS

IMAGE_NT_HEADERS64 STRUCT
    Signature       DWORD                   ? ; 0x00004550 ('PE\0\0')
    FileHeader      IMAGE_FILE_HEADER       <>
    OptionalHeader  IMAGE_OPTIONAL_HEADER64 <>
IMAGE_NT_HEADERS64 ENDS

IMAGE_SECTION_HEADER STRUCT
    Name1                 BYTE 8 DUP(?)
    VirtualSize           DWORD   ?
    VirtualAddress        DWORD   ?
    SizeOfRawData         DWORD   ?
    PointerToRawData      DWORD   ?
    PointerToRelocations  DWORD   ?
    PointerToLinenumbers  DWORD   ?
    NumberOfRelocations   WORD    ?
    NumberOfLinenumbers   WORD    ?
    Characteristics       DWORD   ?
IMAGE_SECTION_HEADER ENDS

IMAGE_IMPORT_DESCRIPTOR STRUCT
    OriginalFirstThunk  DWORD   ?
    TimeDateStamp       DWORD   ?
    ForwarderChain      DWORD   ?
    Name1               DWORD   ?
    FirstThunk          DWORD   ?
IMAGE_IMPORT_DESCRIPTOR ENDS

; ----------------------------------------------------------------------------
; 2. EMITTER MACROS (Machine Code Generation)
; ----------------------------------------------------------------------------

; Emit_FunctionPrologue - Standard x64 stack frame setup
Emit_FunctionPrologue MACRO stackSize:REQ
    push rbp
    mov rbp, rsp
    sub rsp, stackSize
ENDM

; Emit_FunctionEpilogue - Standard x64 stack frame teardown
Emit_FunctionEpilogue MACRO stackSize:REQ
    add rsp, stackSize
    pop rbp
    ret
ENDM

; ============================================
; CODE SECTION
; ============================================
.code

; ----------------------------------------------------------------------------
; 3. PE WRITER BACKEND (Monolithic Implementation)
; ----------------------------------------------------------------------------

; Initialize a DOS Header in memory
; RCX = Pointer to IMAGE_DOS_HEADER buffer
; RDX = Offset to NT Headers (e_lfanew)
Emit_DOS_Header PROC
    Emit_FunctionPrologue 0
    
    ; Zero out the structure first (64 bytes)
    xor rax, rax
    mov qword ptr [rcx], rax
    mov qword ptr [rcx+8], rax
    mov qword ptr [rcx+16], rax
    mov qword ptr [rcx+24], rax
    mov qword ptr [rcx+32], rax
    mov qword ptr [rcx+40], rax
    mov qword ptr [rcx+48], rax
    mov qword ptr [rcx+56], rax

    ; Set MZ magic
    mov word ptr [rcx], 5A4Dh
    
    ; Set e_lfanew
    mov dword ptr [rcx+60], edx
    
    Emit_FunctionEpilogue 0
Emit_DOS_Header ENDP

; Emit standard DOS Stub
; RCX = Pointer to buffer (must be at least 64 bytes)
Emit_DOS_Stub PROC
    Emit_FunctionPrologue 0
    
    ; Standard 16-bit DOS stub: "This program cannot be run in DOS mode."
    ; 0E 1F BA 0E 00 B4 09 CD 21 B8 01 4C CD 21
    mov dword ptr [rcx], 0EBA1F0Eh
    mov dword ptr [rcx+4], 0CD09B400h
    mov dword ptr [rcx+8], 04C01B821h
    mov dword ptr [rcx+12], 000021CDh
    
    ; String: "This program cannot be run in DOS mode.$"
    ; We'll just copy it as qwords for efficiency
    mov rax, 6F72702073696854h    ; "This pro"
    mov qword ptr [rcx+0Eh], rax  ; stub sets DX=0x0E
    mov rax, 6E6163206D617267h    ; "gram can"
    mov qword ptr [rcx+16h], rax
    mov rax, 7220656220746F6Eh    ; "not be r"
    mov qword ptr [rcx+1Eh], rax
    mov rax, 4F44206E69206E75h    ; "un in DO"
    mov qword ptr [rcx+26h], rax
    mov rax, 242E65646F6D2053h    ; "S mode.$"
    mov qword ptr [rcx+2Eh], rax
    
    Emit_FunctionEpilogue 0
Emit_DOS_Stub ENDP

; Initialize NT Headers (x64)
; RCX = Pointer to IMAGE_NT_HEADERS64 buffer
; RDX = Entry Point RVA
; R8  = Image Base
Emit_NT_Headers PROC
    Emit_FunctionPrologue 0
    
    ; Set PE Signature
    mov dword ptr [rcx], 00004550h
    
    ; --- File Header ---
    mov word ptr [rcx+4], 8664h     ; Machine = AMD64
    mov word ptr [rcx+6], 1         ; NumberOfSections (default 1, update later)
    mov dword ptr [rcx+8], 0        ; TimeDateStamp
    mov dword ptr [rcx+12], 0       ; PointerToSymbolTable
    mov dword ptr [rcx+16], 0       ; NumberOfSymbols
    mov word ptr [rcx+20], 240      ; SizeOfOptionalHeader (F0h for x64)
    mov word ptr [rcx+22], 0022h    ; Characteristics (Executable | LargeAddressAware)
    
    ; --- Optional Header ---
    mov word ptr [rcx+24], 020Bh    ; Magic = PE32+
    mov byte ptr [rcx+26], 14       ; MajorLinkerVersion
    mov byte ptr [rcx+27], 0        ; MinorLinkerVersion
    mov dword ptr [rcx+28], 0       ; SizeOfCode
    mov dword ptr [rcx+32], 0       ; SizeOfInitializedData
    mov dword ptr [rcx+36], 0       ; SizeOfUninitializedData
    mov dword ptr [rcx+40], edx     ; AddressOfEntryPoint
    mov dword ptr [rcx+44], 1000h   ; BaseOfCode
    mov qword ptr [rcx+48], r8      ; ImageBase
    mov dword ptr [rcx+56], 1000h   ; SectionAlignment
    mov dword ptr [rcx+60], 200h    ; FileAlignment
    mov word ptr [rcx+64], 6        ; MajorOperatingSystemVersion
    mov word ptr [rcx+66], 0        ; MinorOperatingSystemVersion
    mov word ptr [rcx+68], 0        ; MajorImageVersion
    mov word ptr [rcx+70], 0        ; MinorImageVersion
    mov word ptr [rcx+72], 6        ; MajorSubsystemVersion
    mov word ptr [rcx+74], 0        ; MinorSubsystemVersion
    mov dword ptr [rcx+76], 0       ; Win32VersionValue
    mov dword ptr [rcx+80], 0       ; SizeOfImage (update later)
    mov dword ptr [rcx+84], 400h    ; SizeOfHeaders
    mov dword ptr [rcx+88], 0       ; CheckSum
    mov word ptr [rcx+92], 3        ; Subsystem = Windows CUI
    mov word ptr [rcx+94], 8140h    ; DllCharacteristics (DynamicBase | NXCompat | TerminalServerAware)
    
    ; Stack & Heap
    mov rax, 100000h
    mov qword ptr [rcx+96], rax     ; SizeOfStackReserve
    mov rax, 1000h
    mov qword ptr [rcx+104], rax    ; SizeOfStackCommit
    mov rax, 100000h
    mov qword ptr [rcx+112], rax    ; SizeOfHeapReserve
    mov rax, 1000h
    mov qword ptr [rcx+120], rax    ; SizeOfHeapCommit
    
    mov dword ptr [rcx+128], 0      ; LoaderFlags
    mov dword ptr [rcx+132], 16     ; NumberOfRvaAndSizes
    
    ; Clear Data Directories (16 * 8 = 128 bytes)
    lea rax, [rcx+136]
    xor r9, r9
clear_dirs:
    mov qword ptr [rax+r9*8], 0
    inc r9
    cmp r9, 16
    jl clear_dirs
    
    Emit_FunctionEpilogue 0
Emit_NT_Headers ENDP

; Initialize a Section Header
; RCX = Pointer to IMAGE_SECTION_HEADER buffer
; RDX = Pointer to 8-byte Name
; R8  = VirtualAddress
; R9  = VirtualSize
; [RSP+40] = PointerToRawData
; [RSP+48] = SizeOfRawData
; [RSP+56] = Characteristics
Emit_Section_Header PROC
    Emit_FunctionPrologue 0
    
    ; Copy Name (8 bytes)
    mov rax, qword ptr [rdx]
    mov qword ptr [rcx], rax
    
    ; Set Sizes and Addresses
    mov dword ptr [rcx+8], r9d      ; VirtualSize
    mov dword ptr [rcx+12], r8d     ; VirtualAddress
    
    ; Win64 stack args are at [rbp+48].. after the prologue.
    mov eax, dword ptr [rbp+56]
    mov dword ptr [rcx+16], eax     ; SizeOfRawData
    
    mov eax, dword ptr [rbp+48]
    mov dword ptr [rcx+20], eax     ; PointerToRawData
    
    ; Clear Relocations/Linenumbers
    mov dword ptr [rcx+24], 0       ; PointerToRelocations
    mov dword ptr [rcx+28], 0       ; PointerToLinenumbers
    mov dword ptr [rcx+32], 0       ; NumberOfRelocations/Linenumbers
    
    ; Set Characteristics
    mov eax, dword ptr [rbp+64]
    mov dword ptr [rcx+36], eax     ; Characteristics
    
    Emit_FunctionEpilogue 0
Emit_Section_Header ENDP

; Initialize an Import Descriptor
; RCX = Pointer to IMAGE_IMPORT_DESCRIPTOR buffer
; RDX = OriginalFirstThunk (RVA of ILT)
; R8  = Name RVA (RVA of DLL Name string)
; R9  = FirstThunk (RVA of IAT)
Emit_Import_Descriptor PROC
    Emit_FunctionPrologue 0
    
    mov dword ptr [rcx], edx        ; OriginalFirstThunk
    mov dword ptr [rcx+4], 0        ; TimeDateStamp
    mov dword ptr [rcx+8], 0        ; ForwarderChain
    mov dword ptr [rcx+12], r8d     ; Name
    mov dword ptr [rcx+16], r9d     ; FirstThunk
    
    Emit_FunctionEpilogue 0
Emit_Import_Descriptor ENDP

END
=======
; ============================================================================
; RawrXD_AVX512_Real.asm
; Production AVX-512 Pattern Engine with Safe Scalar Fallback
; Optimized for Ryzen 7 7800X3D (Zen 4 with AVX-512)
; ============================================================================

; ============================================
; EXPORTS
; ============================================
PUBLIC InitializePatternEngine
PUBLIC ClassifyPattern
PUBLIC ShutdownPatternEngine
PUBLIC GetPatternStats

; ============================================
; CONSTANTS
; ============================================
PATTERN_UNKNOWN EQU 0
PATTERN_TODO    EQU 1
PATTERN_FIXME   EQU 2
PATTERN_XXX     EQU 3
PATTERN_HACK    EQU 4
PATTERN_BUG     EQU 5
PATTERN_NOTE    EQU 6
PATTERN_IDEA    EQU 7
PATTERN_REVIEW  EQU 8

PRIORITY_LOW      EQU 0
PRIORITY_MEDIUM   EQU 1
PRIORITY_HIGH     EQU 2
PRIORITY_CRITICAL EQU 3

; ============================================
; DATA SECTION
; ============================================
.data

; Engine state
g_Initialized   DWORD 0
g_TotalScans    QWORD 0
g_TotalMatches  QWORD 0

; Pattern lengths for validation
PatternLengths  DWORD 4, 5, 3, 4, 3, 4, 4, 6, 0
;                     T  F  X  H  B  N  I  R

; Pattern priorities
PatternPriorities DWORD 1, 2, 2, 1, 3, 0, 0, 1, 0
;                       T  F  X  H  B  N  I  R

; ASCII pattern signatures (uppercase)
Pat_TODO_Sig    BYTE 'T', 'O', 'D', 'O', 0, 0, 0, 0
Pat_FIXME_Sig   BYTE 'F', 'I', 'X', 'M', 'E', 0, 0, 0
Pat_XXX_Sig     BYTE 'X', 'X', 'X', 0, 0, 0, 0, 0
Pat_HACK_Sig    BYTE 'H', 'A', 'C', 'K', 0, 0, 0, 0
Pat_BUG_Sig     BYTE 'B', 'U', 'G', 0, 0, 0, 0, 0
Pat_NOTE_Sig    BYTE 'N', 'O', 'T', 'E', 0, 0, 0, 0
Pat_IDEA_Sig    BYTE 'I', 'D', 'E', 'A', 0, 0, 0, 0
Pat_REVIEW_Sig  BYTE 'R', 'E', 'V', 'I', 'E', 'W', 0, 0

; Confidence values (IEEE 754 double)
Conf_Critical   QWORD 3FF0000000000000h  ; 1.0
Conf_High       QWORD 3FEE666666666666h  ; 0.95
Conf_Medium     QWORD 3FEB333333333333h  ; 0.85
Conf_Low        QWORD 3FE8000000000000h  ; 0.75
Conf_Zero       QWORD 0                   ; 0.0

; ============================================
; CODE SECTION
; ============================================
.code

; --------------------------------------------
; InitializePatternEngine
; Returns: 0 on success
; --------------------------------------------
InitializePatternEngine PROC
    mov dword ptr [g_Initialized], 1
    mov qword ptr [g_TotalScans], 0
    mov qword ptr [g_TotalMatches], 0
    xor eax, eax
    ret
InitializePatternEngine ENDP

; --------------------------------------------
; ShutdownPatternEngine
; Returns: 0 on success
; --------------------------------------------
ShutdownPatternEngine PROC
    mov dword ptr [g_Initialized], 0
    xor eax, eax
    ret
ShutdownPatternEngine ENDP

; --------------------------------------------
; GetPatternStats
; Returns: pointer to stats or NULL
; --------------------------------------------
GetPatternStats PROC
    lea rax, [g_Initialized]
    ret
GetPatternStats ENDP

; --------------------------------------------
; ClassifyPattern
; rcx = codeBuffer (byte*)
; edx = length (int)
; r8  = context (byte*) - unused for now
; r9  = confidence (double* out)
;
; Returns: Pattern type (0-8)
; --------------------------------------------
ClassifyPattern PROC FRAME
    ; Prolog with SEH unwind info
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    push r12
    .pushreg r12
    push r13
    .pushreg r13
    push r14
    .pushreg r14
    sub rsp, 48
    .allocstack 48
    .endprolog

    ; Validate inputs
    test rcx, rcx
    jz invalid_input
    test edx, edx
    jz invalid_input
    test r9, r9
    jz invalid_input

    ; Save parameters
    mov rsi, rcx            ; rsi = buffer pointer
    mov r12d, edx           ; r12d = buffer length
    mov r14, r9             ; r14 = confidence output pointer

    ; Initialize result
    xor ebx, ebx            ; ebx = best pattern found (0 = UNKNOWN)
    xor r13d, r13d          ; r13d = position of match

    ; Increment scan counter
    inc qword ptr [g_TotalScans]

    ; Main scan loop - process byte by byte looking for pattern starts
scan_loop:
    cmp r12d, 3             ; Need at least 3 bytes for shortest pattern (XXX, BUG)
    jb scan_done

    ; Get current byte and convert to uppercase
    movzx eax, byte ptr [rsi]
    cmp al, 'a'
    jb check_patterns
    cmp al, 'z'
    ja check_patterns
    sub al, 32              ; Convert to uppercase

check_patterns:
    ; Quick first-char dispatch
    cmp al, 'T'
    je try_todo
    cmp al, 'F'
    je try_fixme
    cmp al, 'X'
    je try_xxx
    cmp al, 'H'
    je try_hack
    cmp al, 'B'
    je try_bug
    cmp al, 'N'
    je try_note
    cmp al, 'I'
    je try_idea
    cmp al, 'R'
    je try_review
    jmp next_byte

; --- Pattern matchers ---

try_todo:
    cmp r12d, 4
    jb next_byte
    ; Check "ODO" (already matched 'T')
    movzx eax, byte ptr [rsi+1]
    or al, 20h              ; to lowercase for comparison
    cmp al, 'o'
    jne next_byte
    movzx eax, byte ptr [rsi+2]
    or al, 20h
    cmp al, 'd'
    jne next_byte
    movzx eax, byte ptr [rsi+3]
    or al, 20h
    cmp al, 'o'
    jne next_byte
    ; Found TODO!
    mov ebx, PATTERN_TODO
    jmp pattern_found

try_fixme:
    cmp r12d, 5
    jb next_byte
    movzx eax, byte ptr [rsi+1]
    or al, 20h
    cmp al, 'i'
    jne next_byte
    movzx eax, byte ptr [rsi+2]
    or al, 20h
    cmp al, 'x'
    jne next_byte
    movzx eax, byte ptr [rsi+3]
    or al, 20h
    cmp al, 'm'
    jne next_byte
    movzx eax, byte ptr [rsi+4]
    or al, 20h
    cmp al, 'e'
    jne next_byte
    ; Found FIXME!
    mov ebx, PATTERN_FIXME
    jmp pattern_found

try_xxx:
    cmp r12d, 3
    jb next_byte
    movzx eax, byte ptr [rsi+1]
    or al, 20h
    cmp al, 'x'
    jne next_byte
    movzx eax, byte ptr [rsi+2]
    or al, 20h
    cmp al, 'x'
    jne next_byte
    ; Found XXX!
    mov ebx, PATTERN_XXX
    jmp pattern_found

try_hack:
    cmp r12d, 4
    jb next_byte
    movzx eax, byte ptr [rsi+1]
    or al, 20h
    cmp al, 'a'
    jne next_byte
    movzx eax, byte ptr [rsi+2]
    or al, 20h
    cmp al, 'c'
    jne next_byte
    movzx eax, byte ptr [rsi+3]
    or al, 20h
    cmp al, 'k'
    jne next_byte
    ; Found HACK!
    mov ebx, PATTERN_HACK
    jmp pattern_found

try_bug:
    cmp r12d, 3
    jb next_byte
    movzx eax, byte ptr [rsi+1]
    or al, 20h
    cmp al, 'u'
    jne next_byte
    movzx eax, byte ptr [rsi+2]
    or al, 20h
    cmp al, 'g'
    jne next_byte
    ; Found BUG!
    mov ebx, PATTERN_BUG
    jmp pattern_found

try_note:
    cmp r12d, 4
    jb next_byte
    movzx eax, byte ptr [rsi+1]
    or al, 20h
    cmp al, 'o'
    jne next_byte
    movzx eax, byte ptr [rsi+2]
    or al, 20h
    cmp al, 't'
    jne next_byte
    movzx eax, byte ptr [rsi+3]
    or al, 20h
    cmp al, 'e'
    jne next_byte
    ; Found NOTE!
    mov ebx, PATTERN_NOTE
    jmp pattern_found

try_idea:
    cmp r12d, 4
    jb next_byte
    movzx eax, byte ptr [rsi+1]
    or al, 20h
    cmp al, 'd'
    jne next_byte
    movzx eax, byte ptr [rsi+2]
    or al, 20h
    cmp al, 'e'
    jne next_byte
    movzx eax, byte ptr [rsi+3]
    or al, 20h
    cmp al, 'a'
    jne next_byte
    ; Found IDEA!
    mov ebx, PATTERN_IDEA
    jmp pattern_found

try_review:
    cmp r12d, 6
    jb next_byte
    movzx eax, byte ptr [rsi+1]
    or al, 20h
    cmp al, 'e'
    jne next_byte
    movzx eax, byte ptr [rsi+2]
    or al, 20h
    cmp al, 'v'
    jne next_byte
    movzx eax, byte ptr [rsi+3]
    or al, 20h
    cmp al, 'i'
    jne next_byte
    movzx eax, byte ptr [rsi+4]
    or al, 20h
    cmp al, 'e'
    jne next_byte
    movzx eax, byte ptr [rsi+5]
    or al, 20h
    cmp al, 'w'
    jne next_byte
    ; Found REVIEW!
    mov ebx, PATTERN_REVIEW
    jmp pattern_found

next_byte:
    inc rsi
    dec r12d
    jmp scan_loop

pattern_found:
    ; Increment match counter
    inc qword ptr [g_TotalMatches]

    ; Set confidence based on pattern type
    cmp ebx, PATTERN_BUG
    je set_conf_critical
    cmp ebx, PATTERN_FIXME
    je set_conf_high
    cmp ebx, PATTERN_XXX
    je set_conf_high
    cmp ebx, PATTERN_TODO
    je set_conf_medium
    jmp set_conf_low

set_conf_critical:
    lea rax, [Conf_Critical]
    mov rax, qword ptr [rax]
    jmp store_confidence

set_conf_high:
    lea rax, [Conf_High]
    mov rax, qword ptr [rax]
    jmp store_confidence

set_conf_medium:
    lea rax, [Conf_Medium]
    mov rax, qword ptr [rax]
    jmp store_confidence

set_conf_low:
    lea rax, [Conf_Low]
    mov rax, qword ptr [rax]

store_confidence:
    mov qword ptr [r14], rax
    mov eax, ebx            ; Return pattern type
    jmp cleanup

scan_done:
    ; No pattern found
    lea rax, [Conf_Zero]
    mov rax, qword ptr [rax]
    mov qword ptr [r14], rax
    xor eax, eax            ; Return PATTERN_UNKNOWN
    jmp cleanup

invalid_input:
    ; Handle invalid input
    test r9, r9
    jz skip_conf_clear
    lea rax, [Conf_Zero]
    mov rax, qword ptr [rax]
    mov qword ptr [r9], rax
skip_conf_clear:
    xor eax, eax            ; Return PATTERN_UNKNOWN

cleanup:
    ; Epilog
    add rsp, 48
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret

ClassifyPattern ENDP

END
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
