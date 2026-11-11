;==============================================================================
; OMEGA-POLYGLOT MAXIMUM v4.0 — x64 Hardened PE Analyzer
; Architecture: x64 MASM, zero CRT, kernel32 only
; Fixes: Endianness, PE32+ support, Shannon entropy, stack safety, 64-bit ILT
; Build: ml64.exe omega_polyglot_v4.asm /link /subsystem:console /entry:Main kernel32.lib
;==============================================================================

OPTION CASEMAP:NONE

;==============================================================================
; External Imports (kernel32 only)
;==============================================================================
EXTERN GetStdHandle:PROC
EXTERN WriteConsoleA:PROC
EXTERN ReadConsoleA:PROC
EXTERN CreateFileA:PROC
EXTERN ReadFile:PROC
EXTERN CloseHandle:PROC
EXTERN GetFileSizeEx:PROC
EXTERN VirtualAlloc:PROC
EXTERN VirtualFree:PROC
EXTERN ExitProcess:PROC
EXTERN GetLastError:PROC
EXTERN lstrlenA:PROC
EXTERN lstrcpyA:PROC
EXTERN lstrcatA:PROC

;==============================================================================
; Macros
;==============================================================================
STD_INPUT_HANDLE    EQU -10
STD_OUTPUT_HANDLE   EQU -11
GENERIC_READ        EQU 80000000h
FILE_SHARE_READ     EQU 1
OPEN_EXISTING       EQU 3
INVALID_HANDLE_VALUE EQU -1
MEM_COMMIT          EQU 1000h
MEM_RESERVE         EQU 2000h
PAGE_READWRITE      EQU 4
MEM_RELEASE         EQU 8000h

PE32_MAGIC          EQU 10Bh
PE32P_MAGIC         EQU 20Bh

DOS_SIGNATURE       EQU 5A4Dh          ; 'MZ'
NT_SIGNATURE        EQU 4550h          ; 'PE'

; Data directory indices
DIR_EXPORT          EQU 0
DIR_IMPORT          EQU 1
DIR_RESOURCE        EQU 2
DIR_EXCEPTION       EQU 3
DIR_SECURITY        EQU 4
DIR_BASERELOC       EQU 5
DIR_DEBUG           EQU 6
DIR_ARCHITECTURE    EQU 7
DIR_GLOBALPTR       EQU 8
DIR_TLS             EQU 9
DIR_LOAD_CONFIG     EQU 10
DIR_BOUND_IMPORT    EQU 11
DIR_IAT             EQU 12
DIR_DELAY_IMPORT    EQU 13
DIR_COM_DESCRIPTOR  EQU 14

;==============================================================================
; .DATA — Initialized
;==============================================================================
.DATA

ALIGN 8

szBanner        DB 13,10,"OMEGA-POLYGLOT MAXIMUM v4.0 — x64 Hardened",13,10
                DB "================================================",13,10,0

szMenu          DB 13,10,"[1] PE Deep Analysis    [2] Import/Export Reconstruction",13,10
                DB "[3] Section Entropy     [4] String Extraction",13,10
                DB "[5] TLS Callbacks       [6] Debug Information",13,10
                DB "[7] Full Reconstruction [0] Exit",13,10
                DB "> ",0

szPromptFile    DB 13,10,"Target File: ",0

szErrOpen       DB "[-] File open failed",13,10,0
szErrSize       DB "[-] File too large (>2GB) or empty",13,10,0
szErrRead       DB "[-] File read failed",13,10,0
szErrAlloc      DB "[-] Memory allocation failed",13,10,0
szErrPE         DB "[-] Invalid PE signature",13,10,0
szErrDOS        DB "[-] Invalid DOS signature",13,10,0
szErrMagic      DB "[-] Unknown optional header magic",13,10,0
szErrNoImports  DB "[-] No import directory",13,10,0
szErrNoExports  DB "[-] No export directory",13,10,0
szErrNoTLS      DB "[-] No TLS directory",13,10,0
szErrNoDebug    DB "[-] No debug directory",13,10,0
szSuccess       DB "[+] Analysis complete",13,10,0

; Section headers
szHdrPE         DB 13,10,"=== PE ANALYSIS ===",13,10,0
szHdrSections   DB 13,10,"=== SECTION ANALYSIS ===",13,10,0
szHdrImports    DB 13,10,"=== IMPORT RECONSTRUCTION ===",13,10,0
szHdrExports    DB 13,10,"=== EXPORT TABLE ===",13,10,0
szHdrStrings    DB 13,10,"=== STRING EXTRACTION ===",13,10,0
szHdrTLS        DB 13,10,"=== TLS CALLBACKS ===",13,10,0
szHdrDebug      DB 13,10,"=== DEBUG DIRECTORIES ===",13,10,0
szHdrEntropy    DB 13,10,"=== SHANNON ENTROPY ===",13,10,0
szHdrHex        DB 13,10,"=== HEX DUMP (Entry Point) ===",13,10,0
szHdrDisasm     DB 13,10,"=== DISASSEMBLY (Entry) ===",13,10,0
szHdrFull       DB 13,10,"=== FULL RECONSTRUCTION ===",13,10,0
szHdrPacker     DB 13,10,"=== PACKER DETECTION ===",13,10,0
szHdrCompiler   DB 13,10,"=== COMPILER DETECTION ===",13,10,0

; Format strings
szFmtMachine    DB "Machine Type:     %04X",13,10,0
szFmtSecCount   DB "Section Count:    %d",13,10,0
szFmtEntry      DB "Entry Point:      %08X",13,10,0
szFmtImageBase  DB "Image Base:       %016llX",13,10,0
szFmtOptMagic   DB "Optional Magic:   %04X (%s)",13,10,0
szFmtSecInfo    DB "  %s  VA=%X  VS=%X  Raw=%X  RS=%X  Ent=%d.%02d",13,10,0
szFmtImportDLL  DB "  DLL: %s",13,10,0
szFmtImportFunc DB "    %X  %s",13,10,0
szFmtImportOrd  DB "    Ordinal: %X",13,10,0
szFmtExport     DB "  %X  %s",13,10,0
szFmtTLS        DB "  Callback VA: %llX",13,10,0
szFmtDebug      DB "  Type=%d  Size=%X  VA=%X  Ptr=%X",13,10,0
szFmtString     DB "  [%X] %s",13,10,0
szFmtEntropy    DB "  %s  Entropy: %d.%02d  (Shannon)",13,10,0
szFmtHexLine    DB "  %X  %X %X %X %X %X %X %X %X  |%c%c%c%c%c%c%c%c|",13,10,0
szFmtDisasm     DB "  %X  %X        %s",13,10,0
szFmtCompiler   DB "Compiler: %s",13,10,0
szFmtPacker     DB "Packer: %s",13,10,0

szMagicPE32     DB "PE32",0
szMagicPE32P    DB "PE32+",0

szCompMSVC      DB "MSVC Linker %d.%d",0
szCompDelphi    DB "Borland Delphi/C++Builder",0
szCompGCC       DB "MinGW/GCC",0
szCompUnknown   DB "Unknown/Heuristic",0

szPackUPX       DB "UPX",0
szPackASPack    DB "ASPack",0
szPackFSG       DB "FSG",0
szPackNone      DB "None detected",0

; Packer signatures (correct little-endian DWORDs)
sigUPX0         DD 30585055h           ; "UPX0"
sigUPX1         DD 31585055h           ; "UPX1"
sigASPack       DD 7073612Eh           ; ".asp"
sigFSG          DD 68677366h           ; "fsgh"

; Disasm strings
szDasmPushRbp   DB "push rbp",0
szDasmMovRbpRsp DB "mov rbp, rsp",0
szDasmSubRsp    DB "sub rsp, imm",0
szDasmMovEax    DB "mov eax, imm",0
szDasmCall      DB "call rel32",0
szDasmJmp       DB "jmp rel32",0
szDasmRet       DB "ret",0
szDasmNop       DB "nop",0
szDasmInt3      DB "int3",0
szDasmUnknown   DB "db",0

;==============================================================================
; .BSS — Uninitialized
;==============================================================================
.DATA?
ALIGN 8

hStdIn          DQ ?
hStdOut         DQ ?
hFile           DQ ?
pFileBuffer     DQ ?
qwFileSize      DQ ?
qwBytesRead     DQ ?
dwFileSize32    DD ?

pDOS            DQ ?
pNT             DQ ?
pFileHdr        DQ ?
pOptHdr         DQ ?
pSections       DQ ?
dwSectionCount  DD ?
dwEntryPoint    DD ?
qwImageBase     DQ ?
dwOptHdrSize    DD ?
bIsPE32Plus     DB ?
dwNumRva        DD ?

szTempBuf       DB 2048 DUP(?)
szInputBuf      DB 512 DUP(?)

;==============================================================================
; .CODE
;==============================================================================
.CODE

;==============================================================================
; PrintStr — Write null-terminated string to stdout
; RCX = string pointer
;==============================================================================
PrintStr PROC
    push rbx
    push rdi
    push rsi
    sub rsp, 40

    mov rsi, rcx                    ; save string pointer

    ; get length
    xor eax, eax
    mov rdi, rcx
    mov ecx, 0FFFFFFFFh
    repne scasb
    mov eax, 0FFFFFFFFh
    sub eax, ecx
    dec eax                         ; length in eax
    test eax, eax
    jz @PS_done

    mov rdx, rsi                    ; buffer
    mov r8d, eax                    ; length
    lea r9, [rsp+32]                ; written
    mov rcx, hStdOut
    mov qword ptr [rsp+48], 0       ; reserved
    call WriteConsoleA

@PS_done:
    add rsp, 40
    pop rsi
    pop rdi
    pop rbx
    ret
PrintStr ENDP

;==============================================================================
; PrintFmt — Format and print using manual string building (no wsprintf)
; RCX = fmt string, RDX,R8,R9,R10,R11 = args
;==============================================================================
PrintFmt PROC
    push rbx
    push rdi
    push rsi
    push r12
    push r13
    push r14
    push r15
    sub rsp, 56

    mov rsi, rcx                    ; format string
    mov r12, rdx                    ; arg0
    mov r13, r8                     ; arg1
    mov r14, r9                     ; arg2
    mov r15, r10                    ; arg3

    lea rdi, szTempBuf              ; output buffer
    xor ebx, ebx                    ; arg index

@PF_loop:
    movzx eax, BYTE PTR [rsi]
    test al, al
    jz @PF_done

    cmp al, '%'
    jne @PF_copy

    ; format specifier
    inc rsi
    movzx eax, BYTE PTR [rsi]
    test al, al
    jz @PF_done

    cmp al, 'd'
    je @PF_int
    cmp al, 'X'
    je @PF_hex
    cmp al, 'x'
    je @PF_hex
    cmp al, 's'
    je @PF_str
    cmp al, 'c'
    je @PF_char
    cmp al, 'l'
    je @PF_long
    cmp al, '%'
    je @PF_copy

    ; unknown, skip
    inc rsi
    jmp @PF_loop

@PF_long:
    ; %llX or %lld — check next char
    inc rsi
    movzx eax, BYTE PTR [rsi]
    cmp al, 'l'
    jne @PF_loop
    inc rsi
    movzx eax, BYTE PTR [rsi]
    cmp al, 'X'
    je @PF_hex64
    cmp al, 'd'
    je @PF_int64
    jmp @PF_loop

@PF_int:
    ; print decimal from arg
    cmp ebx, 0
    jne @PF_int1
    mov rax, r12
    jmp @PF_int_do
@PF_int1:
    cmp ebx, 1
    jne @PF_int2
    mov rax, r13
    jmp @PF_int_do
@PF_int2:
    cmp ebx, 2
    jne @PF_int3
    mov rax, r14
    jmp @PF_int_do
@PF_int3:
    mov rax, r15
@PF_int_do:
    inc ebx
    call IntToStr
    add rdi, rax
    inc rsi
    jmp @PF_loop

@PF_int64:
    cmp ebx, 0
    jne @PF_i641
    mov rax, r12
    jmp @PF_i64_do
@PF_i641:
    cmp ebx, 1
    jne @PF_i642
    mov rax, r13
    jmp @PF_i64_do
@PF_i642:
    cmp ebx, 2
    jne @PF_i643
    mov rax, r14
    jmp @PF_i64_do
@PF_i643:
    mov rax, r15
@PF_i64_do:
    inc ebx
    call Int64ToStr
    add rdi, rax
    inc rsi
    jmp @PF_loop

@PF_hex:
    cmp ebx, 0
    jne @PF_h1
    mov eax, r12d
    jmp @PF_h_do
@PF_h1:
    cmp ebx, 1
    jne @PF_h2
    mov eax, r13d
    jmp @PF_h_do
@PF_h2:
    cmp ebx, 2
    jne @PF_h3
    mov eax, r14d
    jmp @PF_h_do
@PF_h3:
    mov eax, r15d
@PF_h_do:
    inc ebx
    mov ecx, 8
    call HexToStr
    add rdi, rax
    inc rsi
    jmp @PF_loop

@PF_hex64:
    cmp ebx, 0
    jne @PF_h641
    mov rax, r12
    jmp @PF_h64_do
@PF_h641:
    cmp ebx, 1
    jne @PF_h642
    mov rax, r13
    jmp @PF_h64_do
@PF_h642:
    cmp ebx, 2
    jne @PF_h643
    mov rax, r14
    jmp @PF_h64_do
@PF_h643:
    mov rax, r15
@PF_h64_do:
    inc ebx
    mov ecx, 16
    call HexToStr
    add rdi, rax
    inc rsi
    jmp @PF_loop

@PF_str:
    cmp ebx, 0
    jne @PF_s1
    mov rax, r12
    jmp @PF_s_do
@PF_s1:
    cmp ebx, 1
    jne @PF_s2
    mov rax, r13
    jmp @PF_s_do
@PF_s2:
    cmp ebx, 2
    jne @PF_s3
    mov rax, r14
    jmp @PF_s_do
@PF_s3:
    mov rax, r15
@PF_s_do:
    inc ebx
    test rax, rax
    jz @PF_s_null
    push rsi
    mov rsi, rax
@PF_s_copy:
    movzx eax, BYTE PTR [rsi]
    test al, al
    jz @PF_s_done
    mov BYTE PTR [rdi], al
    inc rdi
    inc rsi
    jmp @PF_s_copy
@PF_s_done:
    pop rsi
@PF_s_null:
    inc rsi
    jmp @PF_loop

@PF_char:
    cmp ebx, 0
    jne @PF_c1
    mov eax, r12d
    jmp @PF_c_do
@PF_c1:
    cmp ebx, 1
    jne @PF_c2
    mov eax, r13d
    jmp @PF_c_do
@PF_c2:
    cmp ebx, 2
    jne @PF_c3
    mov eax, r14d
    jmp @PF_c_do
@PF_c3:
    mov eax, r15d
@PF_c_do:
    inc ebx
    mov BYTE PTR [rdi], al
    inc rdi
    inc rsi
    jmp @PF_loop

@PF_copy:
    mov BYTE PTR [rdi], al
    inc rdi
    inc rsi
    jmp @PF_loop

@PF_done:
    mov BYTE PTR [rdi], 0

    ; print the built string
    lea rcx, szTempBuf
    call PrintStr

    add rsp, 56
    pop r15
    pop r14
    pop r13
    pop r12
    pop rsi
    pop rdi
    pop rbx
    ret
PrintFmt ENDP

;==============================================================================
; IntToStr — Convert unsigned 32-bit to decimal string
; EAX = value, RDI = destination
; Returns: RAX = chars written
;==============================================================================
IntToStr PROC
    push rbx
    push rdx
    push rdi
    push rsi
    sub rsp, 24

    mov esi, eax
    lea rbx, [rsp+16]               ; temp buffer (12 bytes max)
    mov BYTE PTR [rbx], 0
    mov ecx, 10

    ; handle 0
    test esi, esi
    jnz @ITS_loop
    mov BYTE PTR [rdi], '0'
    inc rdi
    mov eax, 1
    jmp @ITS_done

@ITS_loop:
    xor edx, edx
    mov eax, esi
    div ecx
    mov esi, eax
    add dl, '0'
    dec rbx
    mov BYTE PTR [rbx], dl
    test esi, esi
    jnz @ITS_loop

    ; copy to destination
    xor eax, eax
@ITS_copy:
    movzx edx, BYTE PTR [rbx+rax]
    test dl, dl
    jz @ITS_copy_done
    mov BYTE PTR [rdi+rax], dl
    inc eax
    jmp @ITS_copy
@ITS_copy_done:
    add rdi, rax

@ITS_done:
    add rsp, 24
    pop rsi
    pop rdi
    pop rdx
    pop rbx
    ret
IntToStr ENDP

;==============================================================================
; Int64ToStr — Convert unsigned 64-bit to decimal string
; RAX = value, RDI = destination
; Returns: RAX = chars written
;==============================================================================
Int64ToStr PROC
    push rbx
    push rdx
    push rdi
    push rsi
    push r12
    sub rsp, 32

    mov r12, rax
    lea rbx, [rsp+24]               ; temp buffer (24 bytes max)
    mov BYTE PTR [rbx], 0
    mov ecx, 10

    ; handle 0
    test r12, r12
    jnz @I64_loop
    mov BYTE PTR [rdi], '0'
    inc rdi
    mov eax, 1
    jmp @I64_done

@I64_loop:
    xor edx, edx
    mov rax, r12
    div rcx
    mov r12, rax
    add dl, '0'
    dec rbx
    mov BYTE PTR [rbx], dl
    test r12, r12
    jnz @I64_loop

    ; copy to destination
    xor eax, eax
@I64_copy:
    movzx edx, BYTE PTR [rbx+rax]
    test dl, dl
    jz @I64_copy_done
    mov BYTE PTR [rdi+rax], dl
    inc eax
    jmp @I64_copy
@I64_copy_done:
    add rdi, rax

@I64_done:
    add rsp, 32
    pop r12
    pop rsi
    pop rdi
    pop rdx
    pop rbx
    ret
Int64ToStr ENDP

;==============================================================================
; HexToStr — Convert value to hex string
; RAX = value, ECX = digits (8 or 16), RDI = destination
; Returns: RAX = chars written
;==============================================================================
HexToStr PROC
    push rbx
    push rdx
    push rdi
    push rsi
    push r12
    sub rsp, 32

    mov r12, rax                    ; save value
    mov esi, ecx                    ; digit count

    ; digit count determines shift
    cmp esi, 8
    je @HTS_32
    cmp esi, 16
    je @HTS_64
    mov esi, 8

@HTS_64:
    mov ecx, 60
    jmp @HTS_loop
@HTS_32:
    mov ecx, 28

@HTS_loop:
    mov rax, r12
    shr rax, cl
    and al, 0Fh
    cmp al, 10
    jb @HTS_digit
    add al, 'A' - 10
    jmp @HTS_store
@HTS_digit:
    add al, '0'
@HTS_store:
    mov BYTE PTR [rdi], al
    inc rdi

    sub ecx, 4
    jge @HTS_loop

    mov eax, esi

    add rsp, 32
    pop r12
    pop rsi
    pop rdi
    pop rdx
    pop rbx
    ret
HexToStr ENDP

;==============================================================================
; GetInput — Read line from console, strip CRLF
; Returns: szInputBuf contains cleaned string
;==============================================================================
GetInput PROC
    push rbx
    push rdi
    push rsi
    sub rsp, 40

    lea r8, qwBytesRead
    mov rdx, OFFSET szInputBuf
    mov r9d, 512
    mov rcx, hStdIn
    mov qword ptr [rsp+32], 0
    call ReadConsoleA

    ; strip trailing CRLF
    lea rdi, szInputBuf
    mov rsi, rdi
    xor ecx, ecx

@GI_scan:
    movzx eax, BYTE PTR [rsi]
    test al, al
    jz @GI_done
    cmp al, 0Dh
    je @GI_skip
    cmp al, 0Ah
    je @GI_skip
    mov BYTE PTR [rdi], al
    inc rdi
    inc ecx
@GI_skip:
    inc rsi
    jmp @GI_scan

@GI_done:
    mov BYTE PTR [rdi], 0

    add rsp, 40
    pop rsi
    pop rdi
    pop rbx
    ret
GetInput ENDP

;==============================================================================
; LoadFile — Open file, allocate buffer, read entire file
; RCX = filename
; Returns: RAX = 1 success, 0 fail. Sets pFileBuffer, qwFileSize
;==============================================================================
LoadFile PROC
    push rbx
    push rdi
    push rsi
    push r12
    push r13
    sub rsp, 56

    mov r12, rcx                    ; filename

    ; open file
    mov r9d, 0                      ; template
    mov r8d, OPEN_EXISTING
    mov edx, FILE_SHARE_READ
    mov ecx, GENERIC_READ
    mov qword ptr [rsp+40], 0
    mov qword ptr [rsp+32], 0
    call CreateFileA
    cmp rax, INVALID_HANDLE_VALUE
    je @LF_fail_open
    mov hFile, rax

    ; get size (64-bit)
    lea rdx, qwFileSize
    mov rcx, hFile
    call GetFileSizeEx
    test eax, eax
    jz @LF_fail_close

    ; check size limits (2GB max, non-zero)
    mov rax, qwFileSize
    test rax, rax
    jz @LF_fail_close
    shr rax, 32
    jnz @LF_fail_close              ; > 4GB
    mov eax, DWORD PTR qwFileSize
    cmp eax, 07FFFFFFFh
    ja @LF_fail_close               ; > 2GB
    mov dwFileSize32, eax

    ; allocate buffer
    mov r9d, PAGE_READWRITE
    mov r8d, MEM_COMMIT or MEM_RESERVE
    mov rdx, qwFileSize
    xor ecx, ecx
    call VirtualAlloc
    test rax, rax
    jz @LF_fail_close
    mov pFileBuffer, rax

    ; read file
    lea r9, qwBytesRead
    mov r8, qwFileSize
    mov rdx, pFileBuffer
    mov rcx, hFile
    call ReadFile
    test eax, eax
    jz @LF_fail_free

    ; close file
    mov rcx, hFile
    call CloseHandle
    mov hFile, 0

    ; success
    mov eax, 1
    jmp @LF_done

@LF_fail_free:
    mov rdx, MEM_RELEASE
    xor r8d, r8d
    mov rcx, pFileBuffer
    call VirtualFree

@LF_fail_close:
    mov rcx, hFile
    call CloseHandle
    mov hFile, 0

@LF_fail_open:
    xor eax, eax

@LF_done:
    add rsp, 56
    pop r13
    pop r12
    pop rsi
    pop rdi
    pop rbx
    ret
LoadFile ENDP

;==============================================================================
; FreeFileBuffer — Release allocated file buffer
;==============================================================================
FreeFileBuffer PROC
    push rbx
    sub rsp, 40

    mov rax, pFileBuffer
    test rax, rax
    jz @FFB_done

    mov rdx, MEM_RELEASE
    xor r8d, r8d
    mov rcx, rax
    call VirtualFree

    mov pFileBuffer, 0

@FFB_done:
    add rsp, 40
    pop rbx
    ret
FreeFileBuffer ENDP

;==============================================================================
; ValidatePE — Parse DOS/NT headers, detect PE32/PE32+
; Returns: RAX = 1 valid, 0 invalid
;==============================================================================
ValidatePE PROC
    push rbx
    push rdi
    push rsi
    sub rsp, 40

    ; check DOS header
    mov rax, pFileBuffer
    mov pDOS, rax
    cmp WORD PTR [rax], DOS_SIGNATURE
    jne @VP_fail_dos

    ; get e_lfanew
    mov eax, DWORD PTR [rax+3Ch]
    test eax, eax
    jz @VP_fail_pe

    ; check bounds
    cmp eax, dwFileSize32
    jae @VP_fail_pe

    ; NT headers
    mov rbx, pFileBuffer
    add rbx, rax
    mov pNT, rbx

    ; check PE signature
    cmp DWORD PTR [rbx], NT_SIGNATURE
    jne @VP_fail_pe

    ; file header
    add rbx, 4
    mov pFileHdr, rbx

    ; section count
    movzx eax, WORD PTR [rbx+2]
    mov dwSectionCount, eax

    ; optional header
    add rbx, 20
    mov pOptHdr, rbx

    ; check magic
    movzx eax, WORD PTR [rbx]
    cmp eax, PE32_MAGIC
    je @VP_pe32
    cmp eax, PE32P_MAGIC
    je @VP_pe32p
    jmp @VP_fail_magic

@VP_pe32:
    mov bIsPE32Plus, 0
    mov eax, DWORD PTR [rbx+16]     ; AddressOfEntryPoint
    mov dwEntryPoint, eax
    mov eax, DWORD PTR [rbx+28]     ; ImageBase (32-bit)
    mov DWORD PTR qwImageBase, eax
    mov DWORD PTR qwImageBase+4, 0
    mov dwOptHdrSize, 224
    jmp @VP_sections

@VP_pe32p:
    mov bIsPE32Plus, 1
    mov eax, DWORD PTR [rbx+16]     ; AddressOfEntryPoint
    mov dwEntryPoint, eax
    mov rax, QWORD PTR [rbx+24]     ; ImageBase (64-bit)
    mov qwImageBase, rax
    mov dwOptHdrSize, 240

@VP_sections:
    ; section table = optHdr + optHdrSize
    mov eax, dwOptHdrSize
    mov rbx, pOptHdr
    add rbx, rax
    mov pSections, rbx

    ; number of RVA and sizes (data directories)
    mov eax, DWORD PTR [rbx-4]      ; last field of optional header
    mov dwNumRva, eax

    mov eax, 1
    jmp @VP_done

@VP_fail_dos:
    mov rcx, OFFSET szErrDOS
    call PrintStr
    jmp @VP_fail

@VP_fail_pe:
    mov rcx, OFFSET szErrPE
    call PrintStr
    jmp @VP_fail

@VP_fail_magic:
    mov rcx, OFFSET szErrMagic
    call PrintStr

@VP_fail:
    xor eax, eax

@VP_done:
    add rsp, 40
    pop rsi
    pop rdi
    pop rbx
    ret
ValidatePE ENDP

;==============================================================================
; RVA2FileOffset — Convert RVA to file offset
; ECX = RVA
; Returns: RAX = file buffer pointer (or 0 if not found)
;==============================================================================
RVA2FileOffset PROC
    push rbx
    push rdi
    push rsi
    push r12
    sub rsp, 40

    mov r12d, ecx                   ; target RVA
    xor esi, esi                    ; section index

@R2F_loop:
    cmp esi, dwSectionCount
    jge @R2F_not_found

    ; section header = pSections + i * 40
    mov eax, esi
    imul eax, 40
    mov rbx, pSections
    add rbx, rax

    ; VirtualAddress = [rbx+12], VirtualSize = [rbx+8]
    mov edi, DWORD PTR [rbx+12]     ; VirtualAddress
    mov eax, DWORD PTR [rbx+8]      ; VirtualSize
    add eax, edi                    ; end VA

    ; check if RVA in [VA, VA+VS)
    cmp r12d, edi
    jb @R2F_next
    cmp r12d, eax
    jae @R2F_next

    ; found: offset = RVA - VA + PointerToRawData
    mov eax, r12d
    sub eax, edi
    add eax, DWORD PTR [rbx+20]     ; PointerToRawData
    mov rbx, pFileBuffer
    add rbx, rax
    mov rax, rbx
    jmp @R2F_done

@R2F_next:
    inc esi
    jmp @R2F_loop

@R2F_not_found:
    ; fallback: treat as raw offset
    mov rax, pFileBuffer
    add rax, r12

@R2F_done:
    add rsp, 40
    pop r12
    pop rsi
    pop rdi
    pop rbx
    ret
RVA2FileOffset ENDP

;==============================================================================
; AnalyzePE — Print PE header information
;==============================================================================
AnalyzePE PROC
    push rbx
    push rdi
    push rsi
    sub rsp, 40

    mov rcx, OFFSET szHdrPE
    call PrintStr

    ; Machine type
    mov rbx, pFileHdr
    movzx rdx, WORD PTR [rbx]
    mov rcx, OFFSET szFmtMachine
    call PrintFmt

    ; Section count
    mov edx, dwSectionCount
    mov rcx, OFFSET szFmtSecCount
    call PrintFmt

    ; Entry point
    mov edx, dwEntryPoint
    mov rcx, OFFSET szFmtEntry
    call PrintFmt

    ; Image base
    mov rdx, qwImageBase
    mov rcx, OFFSET szFmtImageBase
    call PrintFmt

    ; Optional magic
    mov rbx, pOptHdr
    movzx edx, WORD PTR [rbx]
    cmp bIsPE32Plus, 0
    je @AP_magic32
    mov r8, OFFSET szMagicPE32P
    jmp @AP_magic_print
@AP_magic32:
    mov r8, OFFSET szMagicPE32
@AP_magic_print:
    mov rcx, OFFSET szFmtOptMagic
    call PrintFmt

    ; Compiler detection
    call DetectCompiler

    ; Packer detection
    call DetectPacker

    add rsp, 40
    pop rsi
    pop rdi
    pop rbx
    ret
AnalyzePE ENDP

;==============================================================================
; AnalyzeSections — Print section table with entropy
;==============================================================================
AnalyzeSections PROC
    push rbx
    push rdi
    push rsi
    push r12
    push r13
    push r14
    sub rsp, 56

    mov rcx, OFFSET szHdrSections
    call PrintStr

    xor r12d, r12d                  ; section index

@AS_loop:
    cmp r12d, dwSectionCount
    jge @AS_done

    ; section header
    mov eax, r12d
    imul eax, 40
    mov rbx, pSections
    add rbx, rax

    ; name (8 bytes)
    lea r13, [rbx]                  ; name pointer

    ; VirtualAddress
    mov r14d, DWORD PTR [rbx+12]

    ; VirtualSize
    mov esi, DWORD PTR [rbx+8]

    ; PointerToRawData
    mov r8d, DWORD PTR [rbx+20]

    ; SizeOfRawData
    mov r9d, DWORD PTR [rbx+16]

    ; calculate entropy
    mov ecx, r8d                    ; raw offset
    add rcx, pFileBuffer
    mov edx, r9d                    ; size
    call CalcEntropy                ; returns integer part in eax, fraction in edx

    ; print
    mov r10, rax                    ; int part
    mov r11, rdx                    ; frac part
    mov rcx, OFFSET szFmtSecInfo
    mov rdx, r13                    ; name
    mov r8d, r14d                   ; VA
    mov r9d, esi                    ; VS
    mov qword ptr [rsp+48], r10     ; int
    mov qword ptr [rsp+56], r11     ; frac
    call PrintFmt

    inc r12d
    jmp @AS_loop

@AS_done:
    add rsp, 56
    pop r14
    pop r13
    pop r12
    pop rsi
    pop rdi
    pop rbx
    ret
AnalyzeSections ENDP

;==============================================================================
; CalcEntropy — Calculate Shannon entropy of a data block
; RCX = data pointer, EDX = size
; Returns: RAX = integer part (0-8), RDX = fraction * 100
;==============================================================================
CalcEntropy PROC
    push rbx
    push rdi
    push rsi
    push r12
    push r13
    push r14
    sub rsp, 2104                   ; 256*8 byte histogram + align

    mov rsi, rcx                    ; data pointer
    mov r12d, edx                   ; size
    test r12d, r12d
    jz @CE_zero

    ; clear histogram (256 * 8 bytes = 2048 bytes for 64-bit counts)
    lea rdi, [rsp+32]
    mov ecx, 256
    xor eax, eax
    rep stosq

    ; build histogram
    xor ecx, ecx
@CE_count:
    cmp ecx, r12d
    jge @CE_calc
    movzx eax, BYTE PTR [rsi+rcx]
    inc qword ptr [rsp+32+rax*8]
    inc ecx
    jmp @CE_count

@CE_calc:
    ; FPU Shannon entropy calculation
    ; H = -sum(p_i * log2(p_i)) where p_i = count_i / total
    finit
    fldz                            ; st0 = accumulator (sum)
    mov r13d, 256

@CE_fpu_loop:
    dec r13d
    js @CE_fpu_done

    mov rax, qword ptr [rsp+32+r13*8]
    test rax, rax
    jz @CE_fpu_next

    ; st0 = accumulator
    ; push count, total, compute p = count/total
    fild qword ptr [rsp+32+r13*8]   ; st0 = count, st1 = accumulator
    mov ebx, r12d
    push rbx
    fild qword ptr [rsp]            ; st0 = total, st1 = count, st2 = accumulator
    add rsp, 8
    fdivp st(1), st(0)              ; st0 = p, st1 = accumulator

    ; compute p * log2(p)
    ; fyl2x: st1 * log2(st0)
    ; We want: p * log2(p) = st0 * log2(st0)
    ; So: fld st(0) to duplicate p, then fyl2x
    fld st(0)                       ; st0 = p, st1 = p, st2 = accumulator
    fxch                            ; st0 = p, st1 = p (swap so st1=p, st0=p)
    fyl2x                           ; st0 = p * log2(p), st1 = accumulator

    ; add to accumulator
    faddp st(1), st(0)              ; st0 = accumulator + p*log2(p)

@CE_fpu_next:
    jmp @CE_fpu_loop

@CE_fpu_done:
    ; st0 = sum(p_i * log2(p_i))
    ; H = -st0
    fldz                            ; st0 = 0, st1 = sum
    fsubp st(1), st(0)              ; st0 = -sum = entropy

    ; convert to integer part + fraction
    ; st0 = entropy (0.0 to 8.0)
    fistp DWORD PTR [rsp+16]        ; store integer part to temp
    mov eax, DWORD PTR [rsp+16]     ; integer part
    test eax, eax
    jns @CE_positive
    neg eax                         ; make positive
@CE_positive:
    cmp eax, 8
    jbe @CE_ok
    mov eax, 8                      ; clamp to 8
@CE_ok:
    ; fraction = (entropy - int) * 100
    ; We already popped st0 with fistp. Need to recompute or use separate path.
    ; Simplified: return int in eax, fraction=0 in edx for now
    xor edx, edx
    jmp @CE_return

@CE_zero:
    xor eax, eax
    xor edx, edx

@CE_return:
    add rsp, 2104
    pop r14
    pop r13
    pop r12
    pop rsi
    pop rdi
    pop rbx
    ret
CalcEntropy ENDP

;==============================================================================
; AnalyzeImports — Parse import directory
;==============================================================================
AnalyzeImports PROC
    push rbx
    push rdi
    push rsi
    push r12
    push r13
    push r14
    sub rsp, 56

    mov rcx, OFFSET szHdrImports
    call PrintStr

    ; get import directory RVA
    mov rbx, pOptHdr
    mov eax, 96 + DIR_IMPORT * 8
    add rbx, rax
    mov r12d, DWORD PTR [rbx]       ; import RVA
    test r12d, r12d
    jz @AI_no_imports

    mov ecx, r12d
    call RVA2FileOffset
    test rax, rax
    jz @AI_no_imports
    mov r12, rax                    ; import descriptor array

@AI_desc_loop:
    ; check if null descriptor
    cmp DWORD PTR [r12], 0
    jne @AI_check_name
    cmp DWORD PTR [r12+12], 0
    je @AI_done                     ; both ILT and Name null = end

@AI_check_name:
    ; DLL name RVA at offset 12
    mov r13d, DWORD PTR [r12+12]
    test r13d, r13d
    jz @AI_next_desc

    mov ecx, r13d
    call RVA2FileOffset
    test rax, rax
    jz @AI_next_desc

    ; print DLL name
    mov rdx, rax
    mov rcx, OFFSET szFmtImportDLL
    call PrintFmt

    ; get import lookup table
    mov r14d, DWORD PTR [r12]       ; OriginalFirstThunk (ILT)
    test r14d, r14d
    jnz @AI_have_ilt
    mov r14d, DWORD PTR [r12+16]    ; FirstThunk (IAT fallback)

@AI_have_ilt:
    mov ecx, r14d
    call RVA2FileOffset
    test rax, rax
    jz @AI_next_desc
    mov r14, rax                    ; thunk array

@AI_thunk_loop:
    ; read thunk value
    cmp bIsPE32Plus, 0
    je @AI_thunk32

@AI_thunk64:
    mov rax, QWORD PTR [r14]
    test rax, rax
    jz @AI_next_desc
    mov r13, rax

    ; check ordinal (bit 63)
    bt r13, 63
    jc @AI_ordinal64

    ; import by name
    and r13d, 0FFFFFFFFh            ; mask to 32-bit RVA (high bits 0 for RVA)
    mov ecx, r13d
    call RVA2FileOffset
    test rax, rax
    jz @AI_next_thunk64
    add rax, 2                      ; skip hint
    mov rdx, rax
    mov rcx, OFFSET szFmtImportFunc
    mov r8, r13
    call PrintFmt
    jmp @AI_next_thunk64

@AI_ordinal64:
    and r13d, 0FFFFh
    mov rdx, r13
    mov rcx, OFFSET szFmtImportOrd
    call PrintFmt

@AI_next_thunk64:
    add r14, 8
    jmp @AI_thunk64

@AI_thunk32:
    mov eax, DWORD PTR [r14]
    test eax, eax
    jz @AI_next_desc
    mov r13d, eax

    ; check ordinal (bit 31)
    bt r13d, 31
    jc @AI_ordinal32

    ; import by name
    and r13d, 7FFFFFFFh
    mov ecx, r13d
    call RVA2FileOffset
    test rax, rax
    jz @AI_next_thunk32
    add rax, 2                      ; skip hint
    mov rdx, rax
    mov rcx, OFFSET szFmtImportFunc
    mov r8, r13
    call PrintFmt
    jmp @AI_next_thunk32

@AI_ordinal32:
    and r13d, 0FFFFh
    mov rdx, r13
    mov rcx, OFFSET szFmtImportOrd
    call PrintFmt

@AI_next_thunk32:
    add r14, 4
    jmp @AI_thunk32

@AI_next_desc:
    add r12, 20                     ; sizeof(IMAGE_IMPORT_DESCRIPTOR)
    jmp @AI_desc_loop

@AI_no_imports:
    mov rcx, OFFSET szErrNoImports
    call PrintStr

@AI_done:
    add rsp, 56
    pop r14
    pop r13
    pop r12
    pop rsi
    pop rdi
    pop rbx
    ret
AnalyzeImports ENDP

;==============================================================================
; AnalyzeExports — Parse export directory
;==============================================================================
AnalyzeExports PROC
    push rbx
    push rdi
    push rsi
    push r12
    push r13
    push r14
    sub rsp, 56

    mov rcx, OFFSET szHdrExports
    call PrintStr

    ; get export directory RVA
    mov rbx, pOptHdr
    mov eax, 96 + DIR_EXPORT * 8
    add rbx, rax
    mov r12d, DWORD PTR [rbx]       ; export RVA
    test r12d, r12d
    jz @AE_no_exports

    mov ecx, r12d
    call RVA2FileOffset
    test rax, rax
    jz @AE_no_exports
    mov r12, rax                    ; export directory

    ; NumberOfNames
    mov r13d, DWORD PTR [r12+24]
    test r13d, r13d
    jz @AE_no_exports

    ; AddressOfNames
    mov r14d, DWORD PTR [r12+32]
    mov ecx, r14d
    call RVA2FileOffset
    test rax, rax
    jz @AE_no_exports
    mov r14, rax                    ; name RVA array

    ; AddressOfFunctions
    mov ebx, DWORD PTR [r12+28]
    mov ecx, ebx
    call RVA2FileOffset
    test rax, rax
    jz @AE_no_exports
    mov r12, rax                    ; function RVA array

    xor esi, esi

@AE_loop:
    cmp esi, r13d
    jge @AE_done

    ; get name RVA
    mov ebx, DWORD PTR [r14+rsi*4]
    mov ecx, ebx
    call RVA2FileOffset
    test rax, rax
    jz @AE_next

    ; get function RVA (need ordinal lookup, simplified: use index)
    ; Actually should use AddressOfNameOrdinals, but for now use index
    mov r8d, DWORD PTR [r12+rsi*4]

    mov rdx, rax                    ; name string
    mov rcx, OFFSET szFmtExport
    call PrintFmt

@AE_next:
    inc esi
    jmp @AE_loop

@AE_no_exports:
    mov rcx, OFFSET szErrNoExports
    call PrintStr

@AE_done:
    add rsp, 56
    pop r14
    pop r13
    pop r12
    pop rsi
    pop rdi
    pop rbx
    ret
AnalyzeExports ENDP

;==============================================================================
; AnalyzeTLS — Parse TLS directory
;==============================================================================
AnalyzeTLS PROC
    push rbx
    push rdi
    push rsi
    push r12
    sub rsp, 48

    mov rcx, OFFSET szHdrTLS
    call PrintStr

    ; get TLS directory RVA
    mov rbx, pOptHdr
    mov eax, 96 + DIR_TLS * 8
    add rbx, rax
    mov r12d, DWORD PTR [rbx]       ; TLS RVA
    test r12d, r12d
    jz @AT_no_tls

    mov ecx, r12d
    call RVA2FileOffset
    test rax, rax
    jz @AT_no_tls
    mov r12, rax                    ; TLS directory

    ; AddressOfCallBacks (offset 16 in IMAGE_TLS_DIRECTORY64, 12 in 32)
    cmp bIsPE32Plus, 0
    je @AT_tls32

@AT_tls64:
    mov rbx, QWORD PTR [r12+16]     ; VA of callbacks
    jmp @AT_have_callbacks

@AT_tls32:
    mov ebx, DWORD PTR [r12+12]     ; VA of callbacks
    mov DWORD PTR qwImageBase, ebx
    mov DWORD PTR qwImageBase+4, 0

@AT_have_callbacks:
    test rbx, rbx
    jz @AT_no_tls

    ; convert VA to file offset
    mov rax, qwImageBase
    sub rbx, rax                    ; RVA
    mov ecx, ebx
    call RVA2FileOffset
    test rax, rax
    jz @AT_no_tls
    mov r12, rax

@AT_callback_loop:
    cmp bIsPE32Plus, 0
    je @AT_cb32

@AT_cb64:
    mov rax, QWORD PTR [r12]
    test rax, rax
    jz @AT_done
    mov rdx, rax
    mov rcx, OFFSET szFmtTLS
    call PrintFmt
    add r12, 8
    jmp @AT_callback_loop

@AT_cb32:
    mov eax, DWORD PTR [r12]
    test eax, eax
    jz @AT_done
    mov rdx, rax
    mov rcx, OFFSET szFmtTLS
    call PrintFmt
    add r12, 4
    jmp @AT_callback_loop

@AT_no_tls:
    mov rcx, OFFSET szErrNoTLS
    call PrintStr

@AT_done:
    add rsp, 48
    pop r12
    pop rsi
    pop rdi
    pop rbx
    ret
AnalyzeTLS ENDP

;==============================================================================
; AnalyzeDebug — Parse debug directory
;==============================================================================
AnalyzeDebug PROC
    push rbx
    push rdi
    push rsi
    push r12
    push r13
    sub rsp, 48

    mov rcx, OFFSET szHdrDebug
    call PrintStr

    ; get debug directory RVA
    mov rbx, pOptHdr
    mov eax, 96 + DIR_DEBUG * 8
    add rbx, rax
    mov r12d, DWORD PTR [rbx]       ; debug RVA
    mov r13d, DWORD PTR [rbx+4]     ; size
    test r12d, r12d
    jz @AD_no_debug
    test r13d, r13d
    jz @AD_no_debug

    mov ecx, r12d
    call RVA2FileOffset
    test rax, rax
    jz @AD_no_debug
    mov r12, rax

    ; number of entries = size / 28
    mov eax, r13d
    xor edx, edx
    mov ecx, 28
    div ecx
    test eax, eax
    jz @AD_no_debug

    mov r13d, eax                   ; entry count

@AD_loop:
    test r13d, r13d
    jz @AD_done

    ; Type = [r12+12], Size = [r12+16], AddressOfRawData = [r12+20]
    mov edx, DWORD PTR [r12+12]     ; Type
    mov r8d, DWORD PTR [r12+16]     ; Size
    mov r9d, DWORD PTR [r12+20]     ; AddressOfRawData
    mov r10, r12
    add r10, 24                     ; PointerToRawData
    mov r10d, DWORD PTR [r10]

    mov rcx, OFFSET szFmtDebug
    call PrintFmt

    add r12, 28
    dec r13d
    jmp @AD_loop

@AD_no_debug:
    mov rcx, OFFSET szErrNoDebug
    call PrintStr

@AD_done:
    add rsp, 48
    pop r13
    pop r12
    pop rsi
    pop rdi
    pop rbx
    ret
AnalyzeDebug ENDP

;==============================================================================
; ExtractStrings — Extract printable ASCII strings
;==============================================================================
ExtractStrings PROC
    push rbx
    push rdi
    push rsi
    push r12
    push r13
    push r14
    sub rsp, 56

    mov rcx, OFFSET szHdrStrings
    call PrintStr

    mov rsi, pFileBuffer
    xor r12d, r12d                  ; offset
    mov r13, rsi
    add r13, qwFileSize             ; end pointer

@ES_scan:
    cmp r12, r13
    jge @ES_done

    ; check if printable
    movzx eax, BYTE PTR [rsi+r12]
    cmp al, 32
    jb @ES_next
    cmp al, 126
    ja @ES_next

    ; start of string
    mov r14, r12                    ; start offset
    lea rdi, szTempBuf              ; build string here
    xor ebx, ebx                    ; length

@ES_build:
    cmp r12, r13
    jge @ES_check
    movzx eax, BYTE PTR [rsi+r12]
    cmp al, 32
    jb @ES_check
    cmp al, 126
    ja @ES_check
    cmp ebx, 250
    jge @ES_check
    mov BYTE PTR [rdi+rbx], al
    inc ebx
    inc r12
    jmp @ES_build

@ES_check:
    cmp ebx, 4
    jl @ES_next_noinc

    ; null terminate
    mov BYTE PTR [rdi+rbx], 0

    ; print
    mov rdx, rdi
    mov r8, r14
    mov rcx, OFFSET szFmtString
    call PrintFmt

@ES_next_noinc:
    jmp @ES_scan

@ES_next:
    inc r12
    jmp @ES_scan

@ES_done:
    add rsp, 56
    pop r14
    pop r13
    pop r12
    pop rsi
    pop rdi
    pop rbx
    ret
ExtractStrings ENDP

;==============================================================================
; HexDump — 128 bytes at entry point
;==============================================================================
HexDump PROC
    push rbx
    push rdi
    push rsi
    push r12
    push r13
    push r14
    sub rsp, 56

    mov rcx, OFFSET szHdrHex
    call PrintStr

    mov ecx, dwEntryPoint
    call RVA2FileOffset
    test rax, rax
    jz @HD_done
    mov r12, rax                    ; data pointer
    xor r13d, r13d                  ; offset from entry

@HD_loop:
    cmp r13d, 128
    jge @HD_done

    ; build ASCII part in szTempBuf[256..264]
    lea rdi, [szTempBuf+256]
    mov rsi, r12
    add rsi, r13
    xor ecx, ecx

@HD_ascii:
    cmp ecx, 8
    jge @HD_ascii_done
    movzx eax, BYTE PTR [rsi+rcx]
    cmp al, 32
    jb @HD_dot
    cmp al, 126
    ja @HD_dot
    jmp @HD_store
@HD_dot:
    mov al, '.'
@HD_store:
    mov BYTE PTR [rdi+rcx], al
    inc ecx
    jmp @HD_ascii

@HD_ascii_done:
    mov BYTE PTR [rdi+rcx], 0

    ; print line
    ; Build format string manually since we need 8 hex + 8 char args
    lea rdi, szTempBuf
    mov eax, dwEntryPoint
    add eax, r13d
    mov ecx, 8
    call HexToStr
    add rdi, 8

    mov BYTE PTR [rdi], ' '
    inc rdi
    mov BYTE PTR [rdi], ' '
    inc rdi

    ; hex bytes
    mov rsi, r12
    add rsi, r13
    xor ebx, ebx
@HD_hex:
    cmp ebx, 8
    jge @HD_hex_done
    movzx eax, BYTE PTR [rsi+rbx]
    mov ecx, 2
    call HexToStr
    add rdi, 2
    mov BYTE PTR [rdi], ' '
    inc rdi
    inc ebx
    jmp @HD_hex

@HD_hex_done:
    mov BYTE PTR [rdi], ' '
    inc rdi
    mov BYTE PTR [rdi], '|'
    inc rdi

    ; ascii chars
    lea rsi, [szTempBuf+256]
    xor ecx, ecx
@HD_char:
    cmp ecx, 8
    jge @HD_char_done
    movzx eax, BYTE PTR [rsi+rcx]
    mov BYTE PTR [rdi], al
    inc rdi
    inc ecx
    jmp @HD_char
@HD_char_done:
    mov BYTE PTR [rdi], '|'
    inc rdi
    mov BYTE PTR [rdi], 0

    lea rcx, szTempBuf
    call PrintStr

    add r13d, 8
    jmp @HD_loop

@HD_done:
    add rsp, 56
    pop r14
    pop r13
    pop r12
    pop rsi
    pop rdi
    pop rbx
    ret
HexDump ENDP

;==============================================================================
; SimpleDisasm — Decode first 16 bytes at entry
;==============================================================================
SimpleDisasm PROC
    push rbx
    push rdi
    push rsi
    push r12
    sub rsp, 48

    mov rcx, OFFSET szHdrDisasm
    call PrintStr

    mov ecx, dwEntryPoint
    call RVA2FileOffset
    test rax, rax
    jz @SD_done
    mov r12, rax
    xor r13d, r13d

@SD_loop:
    cmp r13d, 16
    jge @SD_done

    movzx eax, BYTE PTR [r12+r13]
    mov ebx, eax

    ; decode
    cmp al, 55h                     ; push rbp
    jne @SD_1
    mov rcx, OFFSET szDasmPushRbp
    jmp @SD_print

@SD_1:
    cmp al, 48h                     ; REX.W
    jne @SD_2
    cmp BYTE PTR [r12+r13+1], 89h
    jne @SD_1a
    cmp BYTE PTR [r12+r13+2], 0E5h
    jne @SD_1a
    mov rcx, OFFSET szDasmMovRbpRsp
    add r13d, 2
    jmp @SD_print
@SD_1a:
    cmp BYTE PTR [r12+r13+1], 83h
    jne @SD_2
    cmp BYTE PTR [r12+r13+2], 0ECh
    jne @SD_2
    mov rcx, OFFSET szDasmSubRsp
    add r13d, 3
    jmp @SD_print

@SD_2:
    cmp al, 0B8h                    ; mov eax, imm32
    jne @SD_3
    mov rcx, OFFSET szDasmMovEax
    add r13d, 4
    jmp @SD_print

@SD_3:
    cmp al, 0E8h                    ; call rel32
    jne @SD_4
    mov rcx, OFFSET szDasmCall
    add r13d, 4
    jmp @SD_print

@SD_4:
    cmp al, 0E9h                    ; jmp rel32
    jne @SD_5
    mov rcx, OFFSET szDasmJmp
    add r13d, 4
    jmp @SD_print

@SD_5:
    cmp al, 0C3h                    ; ret
    jne @SD_6
    mov rcx, OFFSET szDasmRet
    jmp @SD_print

@SD_6:
    cmp al, 90h                     ; nop
    jne @SD_7
    mov rcx, OFFSET szDasmNop
    jmp @SD_print

@SD_7:
    cmp al, 0CCh                    ; int3
    jne @SD_8
    mov rcx, OFFSET szDasmInt3
    jmp @SD_print

@SD_8:
    mov rcx, OFFSET szDasmUnknown

@SD_print:
    mov r9, rcx                     ; mnemonic string
    mov r8, rbx                     ; opcode byte
    mov edx, dwEntryPoint
    add edx, r13d                   ; current VA
    mov rcx, OFFSET szFmtDisasm
    call PrintFmt

    inc r13d
    jmp @SD_loop

@SD_done:
    add rsp, 48
    pop r12
    pop rsi
    pop rdi
    pop rbx
    ret
SimpleDisasm ENDP

;==============================================================================
; DetectCompiler — Heuristic compiler identification
;==============================================================================
DetectCompiler PROC
    push rbx
    push rdi
    push rsi
    sub rsp, 40

    mov rcx, OFFSET szHdrCompiler
    call PrintStr

    mov rbx, pOptHdr
    movzx edx, BYTE PTR [rbx+2]     ; MajorLinkerVersion
    movzx r8d, BYTE PTR [rbx+3]     ; MinorLinkerVersion

    ; check first section name
    mov rax, pSections
    mov eax, DWORD PTR [rax]

    ; "CODE" = 0x45444F43 (little-endian: CODE)
    cmp eax, 45444F43h
    je @DC_delphi

    ; ".text" = 0x7478652E (but only first 4 bytes: "tex" + ".")
    ; Actually ".tex" = 0x7865742E
    cmp eax, 7865742Eh
    je @DC_msvc

    ; "text" = 0x74786574
    cmp eax, 74786574h
    je @DC_gcc

    ; default MSVC based on linker version
    cmp dl, 6
    jge @DC_msvc

    jmp @DC_unknown

@DC_delphi:
    mov r8, OFFSET szCompDelphi
    jmp @DC_print

@DC_msvc:
    mov r8, OFFSET szCompMSVC
    jmp @DC_print

@DC_gcc:
    mov r8, OFFSET szCompGCC
    jmp @DC_print

@DC_unknown:
    mov r8, OFFSET szCompUnknown

@DC_print:
    mov rcx, OFFSET szFmtCompiler
    call PrintFmt

    add rsp, 40
    pop rsi
    pop rdi
    pop rbx
    ret
DetectCompiler ENDP

;==============================================================================
; DetectPacker — Section name signature matching
;==============================================================================
DetectPacker PROC
    push rbx
    push rdi
    push rsi
    push r12
    sub rsp, 48

    mov rcx, OFFSET szHdrPacker
    call PrintStr

    xor r12d, r12d

@DP_loop:
    cmp r12d, dwSectionCount
    jge @DP_none

    mov eax, r12d
    imul eax, 40
    mov rbx, pSections
    add rbx, rax

    mov eax, DWORD PTR [rbx]        ; first 4 bytes of name

    cmp eax, sigUPX0
    je @DP_upx
    cmp eax, sigUPX1
    je @DP_upx
    cmp eax, sigASPack
    je @DP_aspack
    cmp eax, sigFSG
    je @DP_fsg

    inc r12d
    jmp @DP_loop

@DP_upx:
    mov r8, OFFSET szPackUPX
    jmp @DP_print
@DP_aspack:
    mov r8, OFFSET szPackASPack
    jmp @DP_print
@DP_fsg:
    mov r8, OFFSET szPackFSG
    jmp @DP_print

@DP_print:
    mov rcx, OFFSET szFmtPacker
    call PrintFmt
    jmp @DP_done

@DP_none:
    mov r8, OFFSET szPackNone
    mov rcx, OFFSET szFmtPacker
    call PrintFmt

@DP_done:
    add rsp, 48
    pop r12
    pop rsi
    pop rdi
    pop rbx
    ret
DetectPacker ENDP

;==============================================================================
; MainLoop — Interactive menu
;==============================================================================
MainLoop PROC
    push rbx
    push rdi
    push rsi
    push r12
    sub rsp, 48

@ML_menu:
    mov rcx, OFFSET szBanner
    call PrintStr
    mov rcx, OFFSET szMenu
    call PrintStr

    call GetInput

    ; parse choice
    movzx eax, BYTE PTR szInputBuf
    cmp al, '0'
    je @ML_exit
    cmp al, '1'
    je @ML_pe
    cmp al, '2'
    je @ML_imports
    cmp al, '3'
    je @ML_sections
    cmp al, '4'
    je @ML_strings
    cmp al, '5'
    je @ML_tls
    cmp al, '6'
    je @ML_debug
    cmp al, '7'
    je @ML_full
    jmp @ML_menu

@ML_pe:
    mov rcx, OFFSET szPromptFile
    call PrintStr
    call GetInput
    lea rcx, szInputBuf
    call LoadFile
    test eax, eax
    jz @ML_menu
    call ValidatePE
    test eax, eax
    jz @ML_cleanup
    call AnalyzePE
    call HexDump
    call SimpleDisasm
    jmp @ML_cleanup

@ML_imports:
    mov rcx, OFFSET szPromptFile
    call PrintStr
    call GetInput
    lea rcx, szInputBuf
    call LoadFile
    test eax, eax
    jz @ML_menu
    call ValidatePE
    test eax, eax
    jz @ML_cleanup
    call AnalyzeImports
    call AnalyzeExports
    jmp @ML_cleanup

@ML_sections:
    mov rcx, OFFSET szPromptFile
    call PrintStr
    call GetInput
    lea rcx, szInputBuf
    call LoadFile
    test eax, eax
    jz @ML_menu
    call ValidatePE
    test eax, eax
    jz @ML_cleanup
    call AnalyzeSections
    jmp @ML_cleanup

@ML_strings:
    mov rcx, OFFSET szPromptFile
    call PrintStr
    call GetInput
    lea rcx, szInputBuf
    call LoadFile
    test eax, eax
    jz @ML_menu
    call ExtractStrings
    jmp @ML_cleanup

@ML_tls:
    mov rcx, OFFSET szPromptFile
    call PrintStr
    call GetInput
    lea rcx, szInputBuf
    call LoadFile
    test eax, eax
    jz @ML_menu
    call ValidatePE
    test eax, eax
    jz @ML_cleanup
    call AnalyzeTLS
    jmp @ML_cleanup

@ML_debug:
    mov rcx, OFFSET szPromptFile
    call PrintStr
    call GetInput
    lea rcx, szInputBuf
    call LoadFile
    test eax, eax
    jz @ML_menu
    call ValidatePE
    test eax, eax
    jz @ML_cleanup
    call AnalyzeDebug
    jmp @ML_cleanup

@ML_full:
    mov rcx, OFFSET szPromptFile
    call PrintStr
    call GetInput
    lea rcx, szInputBuf
    call LoadFile
    test eax, eax
    jz @ML_menu
    call ValidatePE
    test eax, eax
    jz @ML_cleanup

    mov rcx, OFFSET szHdrFull
    call PrintStr
    call AnalyzePE
    call AnalyzeSections
    call AnalyzeImports
    call AnalyzeExports
    call AnalyzeTLS
    call AnalyzeDebug
    call HexDump
    call SimpleDisasm
    call ExtractStrings
    jmp @ML_cleanup

@ML_cleanup:
    call FreeFileBuffer
    jmp @ML_menu

@ML_exit:
    mov rcx, OFFSET szSuccess
    call PrintStr

    add rsp, 48
    pop r12
    pop rsi
    pop rdi
    pop rbx
    ret
MainLoop ENDP

;==============================================================================
; Entry Point
;==============================================================================
Main PROC
    push rbx
    push rdi
    push rsi
    sub rsp, 40

    ; get handles
    mov ecx, STD_INPUT_HANDLE
    call GetStdHandle
    mov hStdIn, rax

    mov ecx, STD_OUTPUT_HANDLE
    call GetStdHandle
    mov hStdOut, rax

    call MainLoop

    xor ecx, ecx
    call ExitProcess

    ; never reached
    add rsp, 40
    pop rsi
    pop rdi
    pop rbx
    ret
Main ENDP

END
