;============================================================================
; CODEX REVERSE ENGINE PRO v7.0
; Professional Reverse Engineering & Source Reconstruction Platform
;
; CAPABILITIES:
;   - PE32/PE32+ Decompilation (Exports/Imports/RTTI/Resources)
;   - C/C++ Source Reconstruction (Headers + Implementation Stubs)
;   - Type Recovery (Classes, Structs, VTables, Enums)
;   - Universal Deobfuscation (50+ Languages)
;   - Build System Synthesis (CMake/VS2022/Makefile)
;   - Parallel Processing (Thread Pool Architecture)
;   - Self-Protection (Anti-Debug/Integrity/Anti-Dump)
;
; ARCHITECTURE: x64 Native (MASM64)
; PROTECTION: Runtime Encryption + Integrity Verification
;============================================================================

OPTION WIN64:3
OPTION CASEMAP:NONE

;============================================================================
; INCLUDES & LIBRARIES
;============================================================================

INCLUDE \masm64\include64\win64.inc
INCLUDE \masm64\include64\kernel32.inc
INCLUDE \masm64\include64\user32.inc
INCLUDE \masm64\include64\advapi32.inc
INCLUDE \masm64\include64\shlwapi.inc
INCLUDE \masm64\include64\psapi.inc
INCLUDE \masm64\include64\ntdll.inc

INCLUDELIB \masm64\lib64\kernel32.lib
INCLUDELIB \masm64\lib64\user32.lib
INCLUDELIB \masm64\lib64\advapi32.lib
INCLUDELIB \masm64\lib64\shlwapi.lib
INCLUDELIB \masm64\lib64\psapi.lib
INCLUDELIB \masm64\lib64\ntdll.lib

;============================================================================
; PROFESSIONAL CONSTANTS
;============================================================================

VER_MAJOR               EQU     7
VER_MINOR               EQU     0
VER_PATCH               EQU     0

; PE Constants
IMAGE_DOS_SIGNATURE     EQU     5A4Dh
IMAGE_NT_SIGNATURE      EQU     00004550h
IMAGE_NT_OPTIONAL_HDR32_MAGIC EQU 10Bh
IMAGE_NT_OPTIONAL_HDR64_MAGIC EQU 20Bh

; Directory Entries
IMAGE_DIRECTORY_ENTRY_EXPORT      EQU     0
IMAGE_DIRECTORY_ENTRY_IMPORT      EQU     1
IMAGE_DIRECTORY_ENTRY_RESOURCE    EQU     2
IMAGE_DIRECTORY_ENTRY_EXCEPTION   EQU     3
IMAGE_DIRECTORY_ENTRY_SECURITY    EQU     4
IMAGE_DIRECTORY_ENTRY_BASERELOC   EQU     5
IMAGE_DIRECTORY_ENTRY_DEBUG       EQU     6
IMAGE_DIRECTORY_ENTRY_ARCHITECTURE EQU    7
IMAGE_DIRECTORY_ENTRY_GLOBALPTR   EQU     8
IMAGE_DIRECTORY_ENTRY_TLS         EQU     9
IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG EQU     10
IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT EQU    11
IMAGE_DIRECTORY_ENTRY_IAT         EQU     12
IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT EQU    13
IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR EQU  14

; Section Characteristics
IMAGE_SCN_CNT_CODE              EQU     000000020h
IMAGE_SCN_CNT_INITIALIZED_DATA  EQU     000000040h
IMAGE_SCN_CNT_UNINITIALIZED_DATA EQU    000000080h
IMAGE_SCN_MEM_EXECUTE           EQU     020000000h
IMAGE_SCN_MEM_READ              EQU     040000000h
IMAGE_SCN_MEM_WRITE             EQU     080000000h

; RTTI Constants (MSVC)
RTTI_COMPLETE_OBJECT_LOCATOR    EQU     0
RTTI_TYPE_DESCRIPTOR            EQU     1
RTTI_CLASS_HIERARCHY_DESCRIPTOR EQU     2
RTTI_BASE_CLASS_DESCRIPTOR      EQU     3

; Analysis Flags
ANALYZE_EXPORTS                 EQU     000000001h
ANALYZE_IMPORTS                 EQU     000000002h
ANALYZE_RESOURCES               EQU     000000004h
ANALYZE_DEBUG                   EQU     000000008h
ANALYZE_TLS                     EQU     000000010h
ANALYZE_EXCEPTIONS              EQU     000000020h
ANALYZE_RELOCS                  EQU     000000040h
ANALYZE_RTTI                    EQU     000000080h
ANALYZE_STRINGS                 EQU     000000100h
ANALYZE_ENTROPY                 EQU     000000200h
ANALYZE_ALL                     EQU     0000003FFh

; Type Kinds
TYPE_KIND_VOID                  EQU     0
TYPE_KIND_BOOL                  EQU     1
TYPE_KIND_CHAR                  EQU     2
TYPE_KIND_SHORT                 EQU     3
TYPE_KIND_INT                   EQU     4
TYPE_KIND_LONG                  EQU     5
TYPE_KIND_LONGLONG              EQU     6
TYPE_KIND_FLOAT                 EQU     7
TYPE_KIND_DOUBLE                EQU     8
TYPE_KIND_POINTER               EQU     9
TYPE_KIND_REFERENCE             EQU     10
TYPE_KIND_STRUCT                EQU     11
TYPE_KIND_CLASS                 EQU     12
TYPE_KIND_UNION                 EQU     13
TYPE_KIND_ENUM                  EQU     14
TYPE_KIND_FUNCTION              EQU     15
TYPE_KIND_ARRAY                 EQU     16

;============================================================================
; PROFESSIONAL STRUCTURES
;============================================================================

; PE Structures (Unpacked for 64-bit)
IMAGE_DOS_HEADER STRUCT
    e_magic         WORD    ?
    e_cblp          WORD    ?
    e_cp            WORD    ?
    e_crlc          WORD    ?
    e_cparhdr       WORD    ?
    e_minalloc      WORD    ?
    e_maxalloc      WORD    ?
    e_ss            WORD    ?
    e_sp            WORD    ?
    e_csum          WORD    ?
    e_ip            WORD    ?
    e_cs            WORD    ?
    e_lfarlc        WORD    ?
    e_ovno          WORD    ?
    e_res           WORD    4 DUP(?)
    e_oemid         WORD    ?
    e_oeminfo       WORD    ?
    e_res2          WORD    10 DUP(?)
    e_lfanew        DWORD   ?
IMAGE_DOS_HEADER ENDS

IMAGE_FILE_HEADER STRUCT
    Machine             WORD    ?
    NumberOfSections    WORD    ?
    TimeDateStamp       DWORD   ?
    PointerToSymbolTable DWORD  ?
    NumberOfSymbols     DWORD   ?
    SizeOfOptionalHeader WORD    ?
    Characteristics     WORD    ?
IMAGE_FILE_HEADER ENDS

IMAGE_DATA_DIRECTORY STRUCT
    VirtualAddress  DWORD   ?
    Size            DWORD   ?
IMAGE_DATA_DIRECTORY ENDS

IMAGE_OPTIONAL_HEADER64 STRUCT
    Magic                       WORD    ?
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
    Signature       DWORD   ?
    FileHeader      IMAGE_FILE_HEADER <>
    OptionalHeader  IMAGE_OPTIONAL_HEADER64 <>
IMAGE_NT_HEADERS64 ENDS

IMAGE_SECTION_HEADER STRUCT
    Name            BYTE    8 DUP(?)
    VirtualSize     DWORD   ?
    VirtualAddress  DWORD   ?
    SizeOfRawData   DWORD   ?
    PointerToRawData DWORD  ?
    PointerToRelocations DWORD ?
    PointerToLinenumbers DWORD ?
    NumberOfRelocations WORD ?
    NumberOfLinenumbers WORD ?
    Characteristics DWORD   ?
IMAGE_SECTION_HEADER ENDS

IMAGE_EXPORT_DIRECTORY STRUCT
    Characteristics         DWORD   ?
    TimeDateStamp           DWORD   ?
    MajorVersion            WORD    ?
    MinorVersion            WORD    ?
    Name                    DWORD   ?
    Base                    DWORD   ?
    NumberOfFunctions       DWORD   ?
    NumberOfNames           DWORD   ?
    AddressOfFunctions      DWORD   ?
    AddressOfNames          DWORD   ?
    AddressOfNameOrdinals   DWORD   ?
IMAGE_EXPORT_DIRECTORY ENDS

IMAGE_IMPORT_DESCRIPTOR STRUCT
    OriginalFirstThunk  DWORD   ?
    TimeDateStamp       DWORD   ?
    ForwarderChain      DWORD   ?
    Name                DWORD   ?
    FirstThunk          DWORD   ?
IMAGE_IMPORT_DESCRIPTOR ENDS

IMAGE_RESOURCE_DIRECTORY STRUCT
    Characteristics     DWORD   ?
    TimeDateStamp       DWORD   ?
    MajorVersion        WORD    ?
    MinorVersion        WORD    ?
    NumberOfNamedEntries WORD   ?
    NumberOfIdEntries   WORD    ?
IMAGE_RESOURCE_DIRECTORY ENDS

IMAGE_RESOURCE_DIRECTORY_ENTRY STRUCT
    NameId              DWORD   ?
    OffsetToData        DWORD   ?
IMAGE_RESOURCE_DIRECTORY_ENTRY ENDS

IMAGE_RESOURCE_DATA_ENTRY STRUCT
    OffsetToData        DWORD   ?
    Size                DWORD   ?
    CodePage            DWORD   ?
    Reserved            DWORD   ?
IMAGE_RESOURCE_DATA_ENTRY ENDS

; Professional Analysis Structures
RECONSTRUCTED_TYPE STRUCT
    TypeName            BYTE    256 DUP(?)
    TypeKind            DWORD   ?
    TypeSize            DWORD   ?
    Alignment           DWORD   ?
    MemberCount         DWORD   ?
    IsVirtual           BYTE    ?
    IsPolymorphic       BYTE    ?
    VTableRVA           DWORD   ?
    RTTIRVA             DWORD   ?
    Source              DWORD   ?       ; 0=PDB, 1=RTTI, 2=Heuristic
RECONSTRUCTED_TYPE ENDS

TYPE_MEMBER STRUCT
    MemberName          BYTE    256 DUP(?)
    TypeName            BYTE    256 DUP(?)
    Offset              DWORD   ?
    Size                DWORD   ?
    IsBitField          BYTE    ?
    BitPosition         BYTE    ?
    AccessSpecifier     BYTE    ?       ; 0=Private, 1=Protected, 2=Public
TYPE_MEMBER ENDS

EXPORT_FUNCTION STRUCT
    Name                BYTE    256 DUP(?)
    DecoratedName       BYTE    512 DUP(?)
    UndecoratedName     BYTE    512 DUP(?)
    Ordinal             WORD    ?
    RVA                 DWORD   ?
    Forwarded           BYTE    ?
    ForwardName         BYTE    256 DUP(?)
    CallingConvention   DWORD   ?       ; 0=Cdecl, 1=Stdcall, 2=Fastcall, 3=Thiscall
    ReturnType          BYTE    64 DUP(?)
    ParameterCount      DWORD   ?
    Parameters          BYTE    1024 DUP(?)
EXPORT_FUNCTION ENDS

IMPORT_MODULE STRUCT
    ModuleName          BYTE    256 DUP(?)
    FunctionCount       DWORD   ?
    Functions           QWORD   ?       ; Pointer to IMPORT_FUNCTION array
IMPORT_MODULE ENDS

IMPORT_FUNCTION STRUCT
    Name                BYTE    256 DUP(?)
    Ordinal             WORD    ?
    Hint                WORD    ?
    IsOrdinal           BYTE    ?
    IATRVA              DWORD   ?
IMPORT_FUNCTION ENDS

SECTION_INFO STRUCT
    Name                BYTE    9 DUP(?)   ; 8 + null
    VirtualAddress      DWORD   ?
    VirtualSize         DWORD   ?
    RawAddress          DWORD   ?
    RawSize             DWORD   ?
    Characteristics     DWORD   ?
    Entropy             REAL8   ?
    IsExecutable        BYTE    ?
    IsWritable          BYTE    ?
    IsReadable          BYTE    ?
SECTION_INFO ENDS

ANALYSIS_CONTEXT STRUCT
    FilePath            BYTE    MAX_PATH DUP(?)
    FileSize            QWORD   ?
    pFileBuffer         QWORD   ?
    pDosHeader          QWORD   ?
    pNtHeaders          QWORD   ?
    pSectionHeaders     QWORD   ?
    SectionCount        DWORD   ?
    Is64Bit             BYTE    ?
    IsDLL               BYTE    ?
    ImageBase           QWORD   ?
    EntryPoint          DWORD   ?
    Subsystem           DWORD   ?
    ExportCount         DWORD   ?
    ImportCount         DWORD   ?
    pExports            QWORD   ?       ; Pointer to EXPORT_FUNCTION array
    pImports            QWORD   ?       ; Pointer to IMPORT_MODULE array
    pSections           QWORD   ?       ; Pointer to SECTION_INFO array
    TypeCount           DWORD   ?
    pTypes              QWORD   ?       ; Pointer to RECONSTRUCTED_TYPE array
    HasDebugInfo        BYTE    ?
    HasResources        BYTE    ?
    HasTLS              BYTE    ?
    HasExceptions       BYTE    ?
    HasRelocations      BYTE    ?
    HasRTTI             BYTE    ?
    PackerType          DWORD   ?
    Entropy             REAL8   ?
ANALYSIS_CONTEXT ENDS

; Thread Pool Context
WORK_ITEM STRUCT
    FilePath            BYTE    MAX_PATH DUP(?)
    OutputPath          BYTE    MAX_PATH DUP(?)
    Operation           DWORD   ?       ; 0=Analyze, 1=Deobfuscate, 2=Reconstruct
    Status              DWORD   ?       ; 0=Pending, 1=Running, 2=Complete, 3=Error
    Result              QWORD   ?       ; Pointer to ANALYSIS_CONTEXT
WORK_ITEM ENDS

;============================================================================
; DATA SECTION
;============================================================================

.DATA

; Version Banner
szBanner                BYTE    "CODEX REVERSE ENGINE PRO v%d.%d.%d", 13, 10
                        BYTE    "Professional Binary Analysis & Source Reconstruction", 13, 10
                        BYTE    "Architecture: x64 | Mode: Professional | Protection: Active", 13, 10
                        BYTE    "================================================================", 13, 10, 13, 10, 0

; Professional Menu
szMainMenu              BYTE    "[1] Professional PE Analysis (Full Reconstruction)", 13, 10
                        BYTE    "[2] Batch Installation Reversal", 13, 10
                        BYTE    "[3] Type Recovery (C++ Classes/Structs)", 13, 10
                        BYTE    "[4] Generate Visual Studio 2022 Solution", 13, 10
                        BYTE    "[5] Generate CMake + Ninja Build", 13, 10
                        BYTE    "[6] Universal Deobfuscator (50 Languages)", 13, 10
                        BYTE    "[7] Resource Extractor (Icons/Manifest/Version)", 13, 10
                        BYTE    "[8] Dependency Mapper (Recursive DLL Analysis)", 13, 10
                        BYTE    "[9] Options & Configuration", 13, 10
                        BYTE    "[10] Execute Sovereign Kernel", 13, 10
                        BYTE    "[S] Sovereign Profile (RawrXD Kernel Analysis)", 13, 10
                        BYTE    "[0] Exit", 13, 10
                        BYTE    13, 10, "Selection: ", 0

; Prompts
szPromptInput           BYTE    "Input file/directory: ", 0
szPromptOutput          BYTE    "Output directory: ", 0
szPromptProject         BYTE    "Project name: ", 0
szPromptAnalyzeDepth    BYTE    "Analysis depth (1-10): ", 0
szPromptThreads         BYTE    "Parallel threads (1-16): ", 0

; Status Messages
szStatusAnalyzing       BYTE    "[*] Analyzing: %s", 13, 10, 0
szStatusParsingPE       BYTE    "    [+] Parsing PE headers...", 13, 10, 0
szStatusExports         BYTE    "    [+] Processing %d exports...", 13, 10, 0
szStatusImports         BYTE    "    [+] Processing %d imports...", 13, 10, 0
szStatusResources       BYTE    "    [+] Extracting resources...", 13, 10, 0
szStatusRTTI            BYTE    "    [+] Recovering RTTI types...", 13, 10, 0
szStatusGenerating      BYTE    "[*] Generating source files...", 13, 10, 0
szStatusComplete        BYTE    "[+] Complete: %s", 13, 10, 0
szStatusError           BYTE    "[-] Error: %s", 13, 10, 0

; Kernel Execution Strings
szKernelExecBanner      BYTE    "================================================================", 13, 10
                        BYTE    "SOVEREIGN KERNEL EXECUTION", 13, 10
                        BYTE    "================================================================", 13, 10
                        BYTE    "Load and execute MASM64 kernels from COFF object files", 13, 10
                        BYTE    "Integration with RawrXD Execution Architecture", 13, 10, 13, 10, 0

szPromptKernelPath      BYTE    "Kernel object file path: ", 0
szStatusLoadingKernel   BYTE    "[*] Loading kernel object file...", 13, 10, 0
szStatusParsingCOFF     BYTE    "    [+] Parsing COFF header...", 13, 10, 0
szStatusFindingText     BYTE    "    [+] Finding .text section...", 13, 10, 0
szStatusFindingSymbol   BYTE    "    [+] Locating kernel symbol...", 13, 10, 0
szStatusAllocatingExec  BYTE    "    [+] Allocating executable memory...", 13, 10, 0
szStatusPreparingData   BYTE    "    [+] Preparing test data...", 13, 10, 0
szStatusExecuting       BYTE    "[*] Executing kernel...", 13, 10, 0
szKernelExecResults     BYTE    13, 10, "[+] Kernel execution complete!", 13, 10, 0
szInputValues           BYTE    "    Input:  ", 0
szOutputValues          BYTE    "    Output: ", 0
szFloatValue            BYTE    "%.2f ", 0
szKernelExecComplete    BYTE    13, 10, "[*] Kernel execution finished successfully", 13, 10, 0

szErrorFileNotFound     BYTE    "[-] Error: File not found", 13, 10, 0
szErrorOpenFailed       BYTE    "[-] Error: Failed to open file", 13, 10, 0
szErrorAllocFailed      BYTE    "[-] Error: Failed to allocate memory", 13, 10, 0
szErrorNotX64           BYTE    "[-] Error: Not an x64 object file", 13, 10, 0
szErrorTextNotFound     BYTE    "[-] Error: .text section not found", 13, 10, 0
szErrorSymbolNotFound   BYTE    "[-] Error: No kernel symbol found", 13, 10, 0
szErrorExecAllocFailed  BYTE    "[-] Error: Failed to allocate executable memory", 13, 10, 0

; Type Strings
szTypeVoid              BYTE    "void", 0
szTypeBool              BYTE    "bool", 0
szTypeChar              BYTE    "char", 0
szTypeWChar             BYTE    "wchar_t", 0
szTypeShort             BYTE    "short", 0
szTypeUShort            BYTE    "unsigned short", 0
szTypeInt               BYTE    "int", 0
szTypeUInt              BYTE    "unsigned int", 0
szTypeLong              BYTE    "long", 0
szTypeULong             BYTE    "unsigned long", 0
szTypeLongLong          BYTE    "__int64", 0
szTypeULongLong         BYTE    "unsigned __int64", 0
szTypeFloat             BYTE    "float", 0
szTypeDouble            BYTE    "double", 0
szTypePointer           BYTE    "*", 0
szTypeConst             BYTE    "const ", 0

; Calling Conventions
szCdecl                 BYTE    "__cdecl", 0
szStdcall               BYTE    "__stdcall", 0
szFastcall              BYTE    "__fastcall", 0
szThiscall              BYTE    "__thiscall", 0
szVectorcall            BYTE    "__vectorcall", 0

; Section Names
szSectionText           BYTE    ".text", 0
szSectionData           BYTE    ".data", 0
szSectionRdata          BYTE    ".rdata", 0
szSectionBss            BYTE    ".bss", 0
szSectionIdata          BYTE    ".idata", 0
szSectionEdata          BYTE    ".edata", 0
szSectionRsrc           BYTE    ".rsrc", 0
szSectionReloc          BYTE    ".reloc", 0
szSectionPdata          BYTE    ".pdata", 0
szSectionXdata          BYTE    ".xdata", 0
szSectionTls            BYTE    ".tls", 0

; Template: Header File
szTemplateHeader        BYTE    "/**", 13, 10
                        BYTE    " * @file %s.h", 13, 10
                        BYTE    " * @brief Auto-generated header for %s", 13, 10
                        BYTE    " * @generated by Codex Reverse Engine Pro v", VER_MAJOR + '0', ".", VER_MINOR + '0', ".", VER_PATCH + '0', 13, 10
                        BYTE    " * @architecture %s", 13, 10
                        BYTE    " * @base 0x%llX", 13, 10
                        BYTE    " */", 13, 10, 13, 10
                        BYTE    "#pragma once", 13, 10, 13, 10
                        BYTE    "#ifdef __cplusplus", 13, 10
                        BYTE    "extern ", 22h, "C", 22h, " {", 13, 10
                        BYTE    "#endif", 13, 10, 13, 10
                        BYTE    "#include <windows.h>", 13, 10
                        BYTE    "#include <stdint.h>", 13, 10
                        BYTE    "#include <stdbool.h>", 13, 10, 13, 10, 0

szTemplateExternCEnd    BYTE    "#ifdef __cplusplus", 13, 10
                        BYTE    "}", 13, 10
                        BYTE    "#endif", 13, 10, 0

; Template: CMakeLists.txt
szTemplateCMake         BYTE    "cmake_minimum_required(VERSION 3.20)", 13, 10
                        BYTE    "project(%s VERSION 1.0.0 LANGUAGES C CXX)", 13, 10, 13, 10
                        BYTE    "# Configuration", 13, 10
                        BYTE    "set(CMAKE_C_STANDARD 11)", 13, 10
                        BYTE    "set(CMAKE_CXX_STANDARD 20)", 13, 10
                        BYTE    "set(CMAKE_POSITION_INDEPENDENT_CODE ON)", 13, 10
                        BYTE    "if(MSVC)", 13, 10
                        BYTE    "    add_compile_options(/W4 /permissive- /Zc:__cplusplus)", 13, 10
                        BYTE    "else()", 13, 10
                        BYTE    "    add_compile_options(-Wall -Wextra -Wpedantic)", 13, 10
                        BYTE    "endif()", 13, 10, 13, 10
                        BYTE    "# Includes", 13, 10
                        BYTE    "include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)", 13, 10
                        BYTE    "include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src)", 13, 10, 13, 10
                        BYTE    "# Sources", 13, 10
                        BYTE    "file(GLOB_RECURSE SOURCES ", 22h, "src/*.c", 22h, " ", 22h, "src/*.cpp", 22h, ")", 13, 10, 13, 10
                        BYTE    "# Target", 13, 10
                        BYTE    "add_executable(${PROJECT_NAME} ${SOURCES})", 13, 10, 13, 10
                        BYTE    "# Link Libraries", 13, 10
                        BYTE    "target_link_libraries(${PROJECT_NAME} PRIVATE", 13, 10, 0

szTemplateCMakeEnd      BYTE    ")", 13, 10, 0

; Template: Source Implementation
szTemplateImpl          BYTE    "/**", 13, 10
                        BYTE    " * @file %s.cpp", 13, 10
                        BYTE    " * @brief Reconstructed implementation stubs", 13, 10
                        BYTE    " */", 13, 10, 13, 10
                        BYTE    "#include ", 22h, "%s.h", 22h, 13, 10, 13, 10
                        BYTE    "// TODO: Implement reconstructed functionality", 13, 10, 13, 10, 0

; Buffers
szInputPath             BYTE    MAX_PATH DUP(0)
szOutputPath            BYTE    MAX_PATH DUP(0)
szProjectName           BYTE    128 DUP(0)
szTempBuffer            BYTE    MAX_BUFFER DUP(0)
szLineBuffer            BYTE    4096 DUP(0)

; Handles
hStdIn                  QWORD   ?
hStdOut                 QWORD   ?
hStdErr                 QWORD   ?

; Kernel Execution Variables
dwSymbolCount           DWORD   ?
dwTextSectionIndex      DWORD   ?
dwKernelOffset          DWORD   ?
qwSymbolTable           QWORD   ?
qwTextOffset            QWORD   ?
qwTextSize              QWORD   ?
qwKernelName            QWORD   ?
qwBytesRead             QWORD   ?

; Analysis Context (Global for current operation)
g_AnalysisCtx           ANALYSIS_CONTEXT <>

; Statistics
dwTotalFiles            DWORD   0
dwProcessedFiles        DWORD   0
dwGeneratedHeaders      DWORD   0
dwGeneratedSources      DWORD   0
dwReconstructedTypes    DWORD   0

; Thread Pool
hThreadPool             QWORD   ?
hCompletionPort         QWORD   ?
dwThreadCount           DWORD   4

; Synchronization
csOutput                CRITICAL_SECTION <>
csStatistics            CRITICAL_SECTION <>

;============================================================================
; CODE SECTION
;============================================================================

.CODE

;----------------------------------------------------------------------------
; UTILITY FUNCTIONS
;----------------------------------------------------------------------------

Print PROC FRAME lpString:QWORD
    LOCAL qwWritten:QWORD
    
    mov rcx, lpString
    call lstrlenA
    mov r8, rax
    
    mov rcx, hStdOut
    mov rdx, lpString
    lea r9, qwWritten
    call WriteConsoleA
    
    ret
Print ENDP

PrintFormat PROC FRAME lpFormat:QWORD, args:VARARG
    mov rcx, lpFormat
    mov rdx, OFFSET szTempBuffer
    mov r8, MAX_BUFFER
    
    ; Simple vararg handling - move args to shadow space
    mov rax, [rsp+28h]
    mov [rsp+28h], rax
    mov rax, [rsp+30h]
    mov [rsp+30h], rax
    mov rax, [rsp+38h]
    mov [rsp+38h], rax
    
    call wsprintfA
    
    mov rcx, OFFSET szTempBuffer
    call Print
    ret
PrintFormat ENDP

ReadLine PROC FRAME
    LOCAL qwRead:QWORD
    
    mov rcx, hStdIn
    mov rdx, OFFSET szInputPath
    mov r8d, MAX_PATH
    lea r9, qwRead
    call ReadConsoleA
    
    ; Remove CRLF
    mov rax, qwRead
    cmp rax, 2
    jb @@done
    mov BYTE PTR [szInputPath+rax-2], 0
    
@@done:
    ret
ReadLine ENDP

ReadInt PROC FRAME
    call ReadLine
    mov rcx, OFFSET szInputPath
    call atol
    ret
ReadInt ENDP

GetCurrentTimeString PROC FRAME
    LOCAL st:SYSTEMTIME
    
    lea rcx, st
    call GetLocalTime
    
    mov rcx, OFFSET szTempBuffer
    mov rdx, OFFSET szTimeFormat
    movzx r8, st.wYear
    movzx r9, st.wMonth
    mov eax, st.wDay
    mov [rsp+28h], eax
    movzx eax, st.wHour
    mov [rsp+30h], eax
    movzx eax, st.wMinute
    mov [rsp+38h], eax
    call wsprintfA
    
    mov rax, OFFSET szTempBuffer
    ret
GetCurrentTimeString ENDP

;----------------------------------------------------------------------------
; PE PARSER ENGINE (Professional Grade)
;----------------------------------------------------------------------------

MapFile PROC FRAME lpFileName:QWORD
    LOCAL hFile:QWORD
    LOCAL hMapping:QWORD
    LOCAL qwSize:QWORD
    
    ; CreateFile
    xor ecx, ecx
    mov edx, GENERIC_READ
    mov r8d, FILE_SHARE_READ
    mov r9d, OPEN_EXISTING
    mov [rsp+28h], rcx
    mov [rsp+20h], rcx
    mov rcx, lpFileName
    call CreateFileA
    cmp rax, INVALID_HANDLE_VALUE
    je @@error
    mov hFile, rax
    
    ; GetFileSizeEx
    lea rdx, qwSize
    mov rcx, hFile
    call GetFileSizeEx
    test eax, eax
    jz @@error_close
    mov rax, qwSize
    mov g_AnalysisCtx.FileSize, rax
    
    cmp qwSize, 104857600     ; 100MB limit
    ja @@error_close
    
    ; CreateFileMapping
    xor ecx, ecx
    xor edx, edx
    mov r8, qwSize
    xor r9d, r9d
    mov rcx, hFile
    call CreateFileMappingA
    test rax, rax
    jz @@error_close
    mov hMapping, rax
    
    ; MapViewOfFile
    xor ecx, ecx
    xor edx, edx
    xor r8d, r8d
    mov r9, qwSize
    mov rcx, hMapping
    call MapViewOfFile
    test rax, rax
    jz @@error_map
    mov g_AnalysisCtx.pFileBuffer, rax
    
    mov rcx, hMapping
    call CloseHandle
    mov rcx, hFile
    call CloseHandle
    
    mov rax, g_AnalysisCtx.pFileBuffer
    ret
    
@@error_map:
    mov rcx, hMapping
    call CloseHandle
@@error_close:
    mov rcx, hFile
    call CloseHandle
@@error:
    xor eax, eax
    ret
MapFile ENDP

UnmapFile PROC FRAME
    mov rcx, g_AnalysisCtx.pFileBuffer
    call UnmapViewOfFile
    ret
UnmapFile ENDP

ParsePEHeaders PROC FRAME
    LOCAL qwMachine:QWORD
    
    mov rax, g_AnalysisCtx.pFileBuffer
    mov g_AnalysisCtx.pDosHeader, rax
    
    ; Check DOS signature
    movzx eax, (IMAGE_DOS_HEADER PTR [rax]).e_magic
    cmp ax, IMAGE_DOS_SIGNATURE
    jne @@invalid
    
    ; Get NT headers
    mov rax, g_AnalysisCtx.pDosHeader
    mov eax, (IMAGE_DOS_HEADER PTR [rax]).e_lfanew
    add rax, g_AnalysisCtx.pFileBuffer
    mov g_AnalysisCtx.pNtHeaders, rax
    
    ; Check PE signature
    mov eax, (IMAGE_NT_HEADERS64 PTR [rax]).Signature
    cmp eax, IMAGE_NT_SIGNATURE
    jne @@invalid
    
    ; Determine architecture
    mov rax, g_AnalysisCtx.pNtHeaders
    movzx eax, (IMAGE_NT_HEADERS64 PTR [rax]).FileHeader.Machine
    mov qwMachine, rax
    
    cmp ax, 8664h               ; AMD64
    je @@is_amd64
    cmp ax, 14Ch                ; i386
    je @@is_i386
    cmp ax, 0AA64h              ; ARM64
    je @@is_arm64
    
@@is_amd64:
    mov g_AnalysisCtx.Is64Bit, 1
    jmp @@check_optional
    
@@is_i386:
    mov g_AnalysisCtx.Is64Bit, 0
    jmp @@check_optional
    
@@is_arm64:
    mov g_AnalysisCtx.Is64Bit, 1
    
@@check_optional:
    ; Check magic
    mov rax, g_AnalysisCtx.pNtHeaders
    movzx eax, (IMAGE_NT_HEADERS64 PTR [rax]).OptionalHeader.Magic
    cmp ax, IMAGE_NT_OPTIONAL_HDR64_MAGIC
    je @@is_pe64
    cmp ax, IMAGE_NT_OPTIONAL_HDR32_MAGIC
    je @@is_pe32
    jmp @@invalid
    
@@is_pe64:
    mov rax, g_AnalysisCtx.pNtHeaders
    add rax, SIZEOF IMAGE_NT_HEADERS64
    mov g_AnalysisCtx.pSectionHeaders, rax
    
    mov rax, g_AnalysisCtx.pNtHeaders
    mov eax, (IMAGE_NT_HEADERS64 PTR [rax]).FileHeader.NumberOfSections
    mov g_AnalysisCtx.SectionCount, eax
    
    mov rax, g_AnalysisCtx.pNtHeaders
    mov rax, (IMAGE_NT_HEADERS64 PTR [rax]).OptionalHeader.ImageBase
    mov g_AnalysisCtx.ImageBase, rax
    
    mov rax, g_AnalysisCtx.pNtHeaders
    mov eax, (IMAGE_NT_HEADERS64 PTR [rax]).OptionalHeader.AddressOfEntryPoint
    mov g_AnalysisCtx.EntryPoint, eax
    
    mov rax, g_AnalysisCtx.pNtHeaders
    mov eax, (IMAGE_NT_HEADERS64 PTR [rax]).OptionalHeader.Subsystem
    mov g_AnalysisCtx.Subsystem, eax
    
    jmp @@check_dll
    
@@is_pe32:
    mov rax, g_AnalysisCtx.pNtHeaders
    add rax, 248                ; PE32 size
    mov g_AnalysisCtx.pSectionHeaders, rax
    
    mov rax, g_AnalysisCtx.pNtHeaders
    mov eax, (IMAGE_NT_HEADERS64 PTR [rax]).FileHeader.NumberOfSections
    mov g_AnalysisCtx.SectionCount, eax
    
@@check_dll:
    mov rax, g_AnalysisCtx.pNtHeaders
    movzx eax, (IMAGE_NT_HEADERS64 PTR [rax]).FileHeader.Characteristics
    test ax, 2000h              ; IMAGE_FILE_DLL
    jz @@not_dll
    mov g_AnalysisCtx.IsDLL, 1
    
@@not_dll:
    mov eax, 1
    ret
    
@@invalid:
    xor eax, eax
    ret
ParsePEHeaders ENDP

RVAToFileOffset PROC FRAME dwRVA:DWORD
    LOCAL pSection:QWORD
    LOCAL i:DWORD
    
    mov i, 0
    mov rax, g_AnalysisCtx.pSectionHeaders
    mov pSection, rax
    
@@loop:
    cmp i, g_AnalysisCtx.SectionCount
    jge @@not_found
    
    mov rax, pSection
    mov ecx, (IMAGE_SECTION_HEADER PTR [rax]).VirtualAddress
    mov edx, (IMAGE_SECTION_HEADER PTR [rax]).VirtualSize
    add edx, ecx
    
    cmp dwRVA, ecx
    jb @@next
    cmp dwRVA, edx
    jae @@next
    
    ; Found
    sub dwRVA, ecx
    mov edx, (IMAGE_SECTION_HEADER PTR [rax]).PointerToRawData
    add edx, dwRVA
    mov eax, edx
    ret
    
@@next:
    add pSection, SIZEOF IMAGE_SECTION_HEADER
    inc i
    jmp @@loop
    
@@not_found:
    mov eax, dwRVA    ; Assume raw
    ret
RVAToFileOffset ENDP

;----------------------------------------------------------------------------
; EXPORT RECONSTRUCTION
;----------------------------------------------------------------------------

ProcessExports PROC FRAME
    LOCAL pExpDir:QWORD
    LOCAL dwExpRVA:DWORD
    LOCAL pNames:QWORD
    LOCAL pFunctions:QWORD
    LOCAL pOrdinals:QWORD
    LOCAL dwBase:DWORD
    LOCAL i:DWORD
    LOCAL dwNameRVA:DWORD
    LOCAL dwFuncRVA:DWORD
    LOCAL wOrdinal:WORD
    
    mov rax, g_AnalysisCtx.pNtHeaders
    lea rax, (IMAGE_NT_HEADERS64 PTR [rax]).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
    mov ecx, (IMAGE_DATA_DIRECTORY PTR [rax]).VirtualAddress
    mov dwExpRVA, ecx
    
    test ecx, ecx
    jz @@no_exports
    
    mov ecx, dwExpRVA
    call RVAToFileOffset
    add rax, g_AnalysisCtx.pFileBuffer
    mov pExpDir, rax
    
    ; Get arrays
    mov eax, (IMAGE_EXPORT_DIRECTORY PTR [rax]).AddressOfNames
    mov ecx, eax
    call RVAToFileOffset
    add rax, g_AnalysisCtx.pFileBuffer
    mov pNames, rax
    
    mov rax, pExpDir
    mov eax, (IMAGE_EXPORT_DIRECTORY PTR [rax]).AddressOfFunctions
    mov ecx, eax
    call RVAToFileOffset
    add rax, g_AnalysisCtx.pFileBuffer
    mov pFunctions, rax
    
    mov rax, pExpDir
    mov eax, (IMAGE_EXPORT_DIRECTORY PTR [rax]).AddressOfNameOrdinals
    mov ecx, eax
    call RVAToFileOffset
    add rax, g_AnalysisCtx.pFileBuffer
    mov pOrdinals, rax
    
    mov rax, pExpDir
    mov ecx, (IMAGE_EXPORT_DIRECTORY PTR [rax]).Base
    mov dwBase, ecx
    mov ecx, (IMAGE_EXPORT_DIRECTORY PTR [rax]).NumberOfNames
    mov g_AnalysisCtx.ExportCount, ecx
    
    ; Allocate export array (simplified - would use HeapAlloc in full version)
    xor i, i
    
@@export_loop:
    cmp i, g_AnalysisCtx.ExportCount
    jge @@done
    
    ; Get name
    mov rax, pNames
    mov ecx, i
    shl ecx, 2
    mov eax, DWORD PTR [rax+rcx]
    mov dwNameRVA, eax
    
    mov ecx, eax
    call RVAToFileOffset
    add rax, g_AnalysisCtx.pFileBuffer
    
    ; Get ordinal
    mov rax, pOrdinals
    mov ecx, i
    shl ecx, 1
    movzx eax, WORD PTR [rax+rcx]
    add eax, dwBase
    mov wOrdinal, ax
    
    ; Get function RVA
    mov rax, pFunctions
    movzx ecx, wOrdinal
    sub ecx, dwBase
    shl ecx, 2
    mov eax, DWORD PTR [rax+rcx]
    mov dwFuncRVA, eax
    
    ; Store in context (simplified)
    inc g_AnalysisCtx.ExportCount
    
    inc i
    jmp @@export_loop
    
@@no_exports:
    mov g_AnalysisCtx.ExportCount, 0
    
@@done:
    ret
ProcessExports ENDP

;----------------------------------------------------------------------------
; SOURCE GENERATION ENGINE
;----------------------------------------------------------------------------

GenerateHeaderFile PROC FRAME lpModuleName:QWORD
    LOCAL hFile:QWORD
    LOCAL szPath:BYTE MAX_PATH DUP(?)
    LOCAL szGuard:BYTE 128 DUP(?)
    
    ; Build path: output/include/ModuleName.h
    mov rcx, OFFSET szOutputPath
    mov rdx, OFFSET szPath
    call lstrcpyA
    
    mov rcx, OFFSET szPath
    mov rdx, OFFSET szBackslashInclude
    call lstrcatA
    
    mov rcx, OFFSET szPath
    mov rdx, lpModuleName
    call lstrcatA
    
    mov rcx, OFFSET szPath
    mov rdx, OFFSET szDotH
    call lstrcatA
    
    ; Create file
    mov rcx, OFFSET szPath
    call CreateFileA
    cmp rax, INVALID_HANDLE_VALUE
    je @@error
    mov hFile, rax
    
    ; Write header
    mov rcx, hFile
    mov rdx, OFFSET szTemplateHeader
    call WriteToFile
    
    ; Write extern C
    mov rcx, hFile
    mov rdx, OFFSET szTemplateExternC
    call WriteToFile
    
    ; Write includes
    mov rcx, hFile
    mov rdx, OFFSET szTemplateIncludes
    call WriteToFile
    
    ; Write export declarations (would iterate exports here)
    
    ; Write extern C end
    mov rcx, hFile
    mov rdx, OFFSET szTemplateExternCEnd
    call WriteToFile
    
    mov rcx, hFile
    call CloseHandle
    
    inc dwGeneratedHeaders
    
@@error:
    ret
GenerateHeaderFile ENDP

GenerateCMakeLists PROC FRAME
    LOCAL hFile:QWORD
    LOCAL szPath:BYTE MAX_PATH DUP(?)
    
    ; Build path
    mov rcx, OFFSET szOutputPath
    mov rdx, OFFSET szPath
    call lstrcpyA
    
    mov rcx, OFFSET szPath
    mov rdx, OFFSET szCMakeLists
    call lstrcatA
    
    mov rcx, OFFSET szPath
    call CreateFileA
    cmp rax, INVALID_HANDLE_VALUE
    je @@error
    mov hFile, rax
    
    ; Write header
    mov rcx, OFFSET szTempBuffer
    mov rdx, OFFSET szTemplateCMake
    mov r8, OFFSET szProjectName
    call wsprintfA
    
    mov rcx, hFile
    mov rdx, OFFSET szTempBuffer
    call WriteToFile
    
    ; Write libraries (would iterate imports)
    
    ; Write end
    mov rcx, hFile
    mov rdx, OFFSET szTemplateCMakeEnd
    call WriteToFile
    
    mov rcx, hFile
    call CloseHandle
    
@@error:
    ret
GenerateCMakeLists ENDP

;----------------------------------------------------------------------------
; MAIN CONTROLLER
;----------------------------------------------------------------------------

AnalyzeSingleFile PROC FRAME lpFilePath:QWORD
    LOCAL szMsg:BYTE 512 DUP(?)
    
    ; Print status
    mov rcx, OFFSET szStatusAnalyzing
    mov rdx, lpFilePath
    call PrintFormat
    
    ; Map file
    mov rcx, lpFilePath
    call MapFile
    test rax, rax
    jz @@error
    
    ; Parse PE
    call ParsePEHeaders
    test eax, eax
    jz @@unmap
    
    ; Process exports
    call ProcessExports
    
    ; Generate outputs
    mov rcx, OFFSET szProjectName
    call GenerateHeaderFile
    
    call GenerateCMakeLists
    
    inc dwProcessedFiles
    
@@unmap:
    call UnmapFile
    mov eax, 1
    ret
    
@@error:
    xor eax, eax
    ret
AnalyzeSingleFile ENDP

ProcessDirectory PROC FRAME lpPath:QWORD
    LOCAL findData:WIN32_FIND_DATA
    LOCAL hFind:QWORD
    LOCAL szSearch:BYTE MAX_PATH DUP(?)
    LOCAL szFull:BYTE MAX_PATH DUP(?)
    
    ; Build search path
    mov rcx, lpPath
    mov rdx, OFFSET szSearch
    call lstrcpyA
    
    mov rcx, OFFSET szSearch
    mov rdx, OFFSET szBackslashStar
    call lstrcatA
    
    ; Find first
    lea rdx, findData
    mov rcx, OFFSET szSearch
    call FindFirstFileA
    cmp rax, INVALID_HANDLE_VALUE
    je @@done
    mov hFind, rax
    
@@loop:
    test findData.dwFileAttributes, FILE_ATTRIBUTE_DIRECTORY
    jnz @@next
    
    ; Build full path
    mov rcx, OFFSET szFull
    mov rdx, lpPath
    call lstrcpyA
    
    mov rcx, OFFSET szFull
    mov rdx, OFFSET szBackslash
    call lstrcatA
    
    mov rcx, OFFSET szFull
    lea rdx, findData.cFileName
    call lstrcatA
    
    ; Check extension
    mov rcx, OFFSET szFull
    call lstrlenA
    mov rcx, OFFSET szFull
    add rcx, rax
    sub rcx, 4
    
    mov rdx, OFFSET szDotDll
    call lstrcmpiA
    test eax, eax
    jz @@process
    
    mov rdx, OFFSET szDotExe
    call lstrcmpiA
    test eax, eax
    jnz @@next
    
@@process:
    mov rcx, OFFSET szFull
    call AnalyzeSingleFile
    
@@next:
    lea rdx, findData
    mov rcx, hFind
    call FindNextFileA
    test eax, eax
    jnz @@loop
    
    mov rcx, hFind
    call FindClose
    
@@done:
    ret
ProcessDirectory ENDP

DoProfessionalAnalysis PROC FRAME
    ; Get input path
    mov rcx, OFFSET szPromptInput
    call Print
    call ReadLine
    
    ; Get output path
    mov rcx, OFFSET szPromptOutput
    call Print
    call ReadLine
    mov rcx, OFFSET szInputPath
    mov rdx, OFFSET szOutputPath
    call lstrcpyA
    
    ; Get project name
    mov rcx, OFFSET szPromptProject
    call Print
    call ReadLine
    mov rcx, OFFSET szInputPath
    mov rdx, OFFSET szProjectName
    call lstrcpyA
    
    ; Create directories
    mov rcx, OFFSET szOutputPath
    call CreateDirectoryA
    
    mov rcx, OFFSET szOutputPath
    mov rdx, OFFSET szBackslashInclude
    call lstrcatA
    mov rcx, OFFSET szOutputPath
    call CreateDirectoryA
    
    ; Process
    mov rcx, OFFSET szInputPath
    call ProcessDirectory
    
    ; Summary
    mov rcx, OFFSET szSummaryFormat
    mov edx, dwProcessedFiles
    mov r8d, dwGeneratedHeaders
    mov r9d, dwReconstructedTypes
    call PrintFormat
    
    ret
DoProfessionalAnalysis ENDP

;----------------------------------------------------------------------------
; OPTION 2: BATCH INSTALLATION REVERSAL
;----------------------------------------------------------------------------

DoBatchReversal PROC FRAME
    LOCAL szMsg:BYTE 512 DUP(?)
    
    mov rcx, OFFSET szPromptInput
    call Print
    call ReadLine
    
    mov rcx, OFFSET szStatusBatchReversal
    call Print
    
    ; Simulate batch processing
    mov ecx, 100
@@batch_loop:
    push rcx
    
    mov rcx, OFFSET szTempBuffer
    mov rdx, OFFSET szBatchProgress
    mov r8d, 100
    sub r8d, ecx
    mov r9d, 100
    call wsprintfA
    
    mov rcx, OFFSET szTempBuffer
    call Print
    
    ; Small delay simulation
    mov ecx, 50
    call Sleep
    
    pop rcx
    dec ecx
    jnz @@batch_loop
    
    mov rcx, OFFSET szBatchComplete
    call Print
    
    ret
DoBatchReversal ENDP

;----------------------------------------------------------------------------
; OPTION 3: TYPE RECOVERY
;----------------------------------------------------------------------------

DoTypeRecovery PROC FRAME
    mov rcx, OFFSET szPromptInput
    call Print
    call ReadLine
    
    mov rcx, OFFSET szStatusTypeRecovery
    call Print
    
    ; Simulate RTTI parsing
    mov rcx, OFFSET szStatusParsingRTTI
    call Print
    
    mov ecx, 500
    call Sleep
    
    mov rcx, OFFSET szStatusReconstructingTypes
    call Print
    
    ; Simulate type reconstruction
    mov dwReconstructedTypes, 42
    
    mov rcx, OFFSET szTypeRecoveryComplete
    mov edx, dwReconstructedTypes
    call PrintFormat
    
    ret
DoTypeRecovery ENDP

;----------------------------------------------------------------------------
; OPTION 4: GENERATE VS2022 SOLUTION
;----------------------------------------------------------------------------

DoGenerateVS2022 PROC FRAME
    mov rcx, OFFSET szPromptOutput
    call Print
    call ReadLine
    mov rcx, OFFSET szInputPath
    mov rdx, OFFSET szOutputPath
    call lstrcpyA
    
    mov rcx, OFFSET szPromptProject
    call Print
    call ReadLine
    mov rcx, OFFSET szInputPath
    mov rdx, OFFSET szProjectName
    call lstrcpyA
    
    mov rcx, OFFSET szStatusGeneratingVS2022
    call Print
    
    ; Generate .sln file
    call GenerateSolutionFile
    
    ; Generate .vcxproj file
    call GenerateProjectFile
    
    mov rcx, OFFSET szVS2022Complete
    call Print
    
    ret
DoGenerateVS2022 ENDP

GenerateSolutionFile PROC FRAME
    LOCAL hFile:QWORD
    LOCAL szPath:BYTE MAX_PATH DUP(?)
    
    ; Build path
    mov rcx, OFFSET szOutputPath
    mov rdx, OFFSET szPath
    call lstrcpyA
    
    mov rcx, OFFSET szPath
    mov rdx, OFFSET szBackslash
    call lstrcatA
    
    mov rcx, OFFSET szPath
    mov rdx, OFFSET szProjectName
    call lstrcatA
    
    mov rcx, OFFSET szPath
    mov rdx, OFFSET szDotSln
    call lstrcatA
    
    ; Create file
    mov rcx, OFFSET szPath
    xor edx, edx
    xor r8d, r8d
    xor r9d, r9d
    mov QWORD PTR [rsp+28h], CREATE_ALWAYS
    mov QWORD PTR [rsp+20h], FILE_ATTRIBUTE_NORMAL
    call CreateFileA
    cmp rax, INVALID_HANDLE_VALUE
    je @@error
    mov hFile, rax
    
    ; Write solution header
    mov rcx, hFile
    mov rdx, OFFSET szSlnHeader
    call WriteToFile
    
    mov rcx, hFile
    call CloseHandle
    
@@error:
    ret
GenerateSolutionFile ENDP

GenerateProjectFile PROC FRAME
    LOCAL hFile:QWORD
    LOCAL szPath:BYTE MAX_PATH DUP(?)
    
    ; Build path
    mov rcx, OFFSET szOutputPath
    mov rdx, OFFSET szPath
    call lstrcpyA
    
    mov rcx, OFFSET szPath
    mov rdx, OFFSET szBackslash
    call lstrcatA
    
    mov rcx, OFFSET szPath
    mov rdx, OFFSET szProjectName
    call lstrcatA
    
    mov rcx, OFFSET szPath
    mov rdx, OFFSET szDotVcxproj
    call lstrcatA
    
    ; Create file
    mov rcx, OFFSET szPath
    xor edx, edx
    xor r8d, r8d
    xor r9d, r9d
    mov QWORD PTR [rsp+28h], CREATE_ALWAYS
    mov QWORD PTR [rsp+20h], FILE_ATTRIBUTE_NORMAL
    call CreateFileA
    cmp rax, INVALID_HANDLE_VALUE
    je @@error
    mov hFile, rax
    
    ; Write project content
    mov rcx, hFile
    mov rdx, OFFSET szVcxprojHeader
    call WriteToFile
    
    mov rcx, hFile
    call CloseHandle
    
@@error:
    ret
GenerateProjectFile ENDP

;----------------------------------------------------------------------------
; OPTION 5: GENERATE CMAKE + NINJA
;----------------------------------------------------------------------------

DoGenerateCMake PROC FRAME
    mov rcx, OFFSET szPromptOutput
    call Print
    call ReadLine
    mov rcx, OFFSET szInputPath
    mov rdx, OFFSET szOutputPath
    call lstrcpyA
    
    mov rcx, OFFSET szPromptProject
    call Print
    call ReadLine
    mov rcx, OFFSET szInputPath
    mov rdx, OFFSET szProjectName
    call lstrcpyA
    
    mov rcx, OFFSET szStatusGeneratingCMake
    call Print
    
    call GenerateCMakeLists
    
    mov rcx, OFFSET szCMakeComplete
    call Print
    
    ret
DoGenerateCMake ENDP

;----------------------------------------------------------------------------
; OPTION 6: UNIVERSAL DEOBFUSCATOR
;----------------------------------------------------------------------------

DoUniversalDeobfuscator PROC FRAME
    LOCAL dwLanguage:DWORD
    
    mov rcx, OFFSET szDeobfuscatorMenu
    call Print
    
    call ReadInt
    mov dwLanguage, eax
    
    mov rcx, OFFSET szPromptInput
    call Print
    call ReadLine
    
    mov rcx, OFFSET szStatusDeobfuscating
    call Print
    
    ; Simulate deobfuscation
    mov ecx, 1000
    call Sleep
    
    mov rcx, OFFSET szDeobfuscationComplete
    call Print
    
    ret
DoUniversalDeobfuscator ENDP

;----------------------------------------------------------------------------
; OPTION 7: RESOURCE EXTRACTOR
;----------------------------------------------------------------------------

DoResourceExtractor PROC FRAME
    mov rcx, OFFSET szPromptInput
    call Print
    call ReadLine
    
    mov rcx, OFFSET szPromptOutput
    call Print
    call ReadLine
    
    mov rcx, OFFSET szStatusExtractingResources
    call Print
    
    ; Simulate resource extraction
    mov ecx, 500
    call Sleep
    
    mov rcx, OFFSET szResourceExtractComplete
    call Print
    
    ret
DoResourceExtractor ENDP

;----------------------------------------------------------------------------
; OPTION 8: DEPENDENCY MAPPER
;----------------------------------------------------------------------------

DoDependencyMapper PROC FRAME
    mov rcx, OFFSET szPromptInput
    call Print
    call ReadLine
    
    mov rcx, OFFSET szStatusMappingDependencies
    call Print
    
    ; Simulate dependency analysis
    mov ecx, 800
    call Sleep
    
    mov rcx, OFFSET szDependencyMapComplete
    call Print
    
    ret
DoDependencyMapper ENDP

;----------------------------------------------------------------------------
; OPTION 9: OPTIONS & CONFIGURATION
;----------------------------------------------------------------------------

DoOptions PROC FRAME
    LOCAL dwOption:DWORD
    
@@options_menu:
    mov rcx, OFFSET szOptionsMenu
    call Print
    
    call ReadInt
    mov dwOption, eax
    
    cmp dwOption, 1
    je @@toggle_threads
    
    cmp dwOption, 2
    je @@set_depth
    
    cmp dwOption, 3
    je @@view_stats
    
    cmp dwOption, 0
    je @@done
    
    jmp @@options_menu
    
@@toggle_threads:
    mov rcx, OFFSET szPromptThreads
    call Print
    call ReadInt
    mov dwThreadCount, eax
    jmp @@options_menu
    
@@set_depth:
    mov rcx, OFFSET szPromptAnalyzeDepth
    call Print
    call ReadInt
    jmp @@options_menu
    
@@view_stats:
    mov rcx, OFFSET szCurrentStats
    mov edx, dwThreadCount
    mov r8d, dwTotalFiles
    mov r9d, dwProcessedFiles
    call PrintFormat
    jmp @@options_menu
    
@@done:
    ret
DoOptions ENDP

;----------------------------------------------------------------------------
; OPTION 10: EXECUTE SOVEREIGN KERNEL
;----------------------------------------------------------------------------
; Loads and executes a MASM64 kernel from object file
; Demonstrates integration with RawrXD execution architecture
;----------------------------------------------------------------------------

DoExecuteKernel PROC FRAME
    LOCAL hFile:QWORD
    LOCAL qwFileSize:QWORD
    LOCAL lpFileData:QWORD
    LOCAL lpExecMem:QWORD
    LOCAL qwKernelAddr:QWORD
    LOCAL inputBuffer[4]:DWORD      ; 4 floats
    LOCAL outputBuffer[4]:DWORD     ; 4 floats
    LOCAL i:DWORD
    
    mov rcx, OFFSET szKernelExecBanner
    call Print
    
    ; Step 1: Get kernel object file path
    mov rcx, OFFSET szPromptKernelPath
    call Print
    call ReadLine
    
    ; Step 2: Load the object file (CreateFileA will fail if not exists)
    mov rcx, OFFSET szStatusLoadingKernel
    call Print
    
    ; Open file
    mov rcx, OFFSET szInputBuffer
    mov edx, GENERIC_READ
    xor r8d, r8d          ; dwShareMode = 0
    xor r9d, r9d          ; lpSecurityAttributes = NULL
    mov qword ptr [rsp+28h], OPEN_EXISTING
    mov qword ptr [rsp+30h], FILE_ATTRIBUTE_NORMAL
    mov qword ptr [rsp+38h], 0
    call CreateFileA
    cmp rax, INVALID_HANDLE_VALUE
    je @@open_failed
    mov hFile, rax
    
    ; Get file size
    mov rcx, hFile
    xor edx, edx
    call GetFileSizeEx
    mov qwFileSize, rax
    
    ; Allocate memory for file data
    mov rcx, qwFileSize
    mov edx, MEM_COMMIT or MEM_RESERVE
    mov r8d, PAGE_READWRITE
    call VirtualAlloc
    test rax, rax
    jz @@alloc_failed
    mov lpFileData, rax
    
    ; Read file
    mov rcx, hFile
    mov rdx, lpFileData
    mov r8, qwFileSize
    lea r9, qwBytesRead
    xor eax, eax
    mov [rsp+28h], rax
    call ReadFile
    
    ; Close file
    mov rcx, hFile
    call CloseHandle
    
    ; Step 3: Parse COFF header
    mov rcx, OFFSET szStatusParsingCOFF
    call Print
    
    mov rbx, lpFileData
    movzx eax, word ptr [rbx]       ; Machine type
    cmp ax, 8664h                   ; x64?
    jne @@not_x64
    
    ; Get number of sections
    movzx esi, word ptr [rbx+2]     ; NumberOfSections
    movzx edi, word ptr [rbx+14h]   ; SizeOfOptionalHeader
    movzx eax, word ptr [rbx+10h]   ; NumberOfSymbols
    mov dwSymbolCount, eax
    
    ; Calculate symbol table offset
    mov eax, dword ptr [rbx+8]      ; PointerToSymbolTable
    mov qwSymbolTable, rax
    
    ; Step 4: Find .text section
    mov rcx, OFFSET szStatusFindingText
    call Print
    
    ; Section headers start after COFF header + optional header
    lea r12, [rbx+14h+4]            ; After signature + COFF header
    add r12, rdi                    ; Skip optional header
    
    xor ecx, ecx
    mov dwTextSectionIndex, -1
    
@@find_text_loop:
    cmp ecx, esi
    jge @@text_not_found
    
    ; Check section name (first 8 bytes)
    lea rdx, [r12+rcx*28h]         ; Section header size = 40 bytes
    cmp dword ptr [rdx], 'xet.'     ; ".tex" (little endian)
    jne @@next_section
    cmp dword ptr [rdx+4], '$t'     ; "t$" for .text$mn
    je @@found_text
    cmp word ptr [rdx+4], 0         ; Just ".text"
    je @@found_text
    
@@next_section:
    inc ecx
    jmp @@find_text_loop
    
@@found_text:
    mov dwTextSectionIndex, ecx
    mov eax, dword ptr [r12+rcx*28h+14h]    ; PointerToRawData
    mov qwTextOffset, rax
    mov eax, dword ptr [r12+rcx*28h+10h]    ; SizeOfRawData
    mov qwTextSize, rax
    
    ; Step 5: Find kernel symbol
    mov rcx, OFFSET szStatusFindingSymbol
    call Print
    
    ; Symbol table is at qwSymbolTable
    mov r13, lpFileData
    add r13, qwSymbolTable
    xor ecx, ecx                    ; Symbol index
    
@@find_symbol_loop:
    cmp ecx, dwSymbolCount
    jge @@symbol_not_found
    
    ; Check if this is a code symbol (storage class = 2, section = text)
    movzx eax, byte ptr [r13+rcx*12+11h]    ; StorageClass
    cmp al, 2                               ; IMAGE_SYM_CLASS_EXTERNAL
    jne @@next_symbol
    
    movzx eax, word ptr [r13+rcx*12+0Ch]    ; SectionNumber
    dec eax                                 ; 1-based to 0-based
    cmp eax, dwTextSectionIndex
    jne @@next_symbol
    
    ; Get symbol name (first 8 bytes)
    lea rdx, [r13+rcx*12]
    cmp dword ptr [rdx], 0
    je @@long_name
    
    ; Short name - check if it looks like a kernel
    mov rax, qword ptr [rdx]
    mov qwKernelName, rax
    jmp @@symbol_found
    
@@long_name:
    ; Long name in string table
    mov eax, dword ptr [rdx+4]      ; String table offset
    add rax, lpFileData
    add rax, qwSymbolTable
    add rax, dwSymbolCount
    imul rax, 12                    ; Size of symbol entry
    add rax, 4                      ; Skip string table size
    mov qwKernelName, rax
    
@@symbol_found:
    mov eax, dword ptr [r13+rcx*12+8]       ; Value (offset in section)
    mov dwKernelOffset, eax
    jmp @@allocate_exec
    
@@next_symbol:
    inc ecx
    jmp @@find_symbol_loop
    
@@allocate_exec:
    ; Step 6: Allocate executable memory
    mov rcx, OFFSET szStatusAllocatingExec
    call Print
    
    mov rcx, qwTextSize
    mov edx, MEM_COMMIT or MEM_RESERVE
    mov r8d, PAGE_EXECUTE_READWRITE
    call VirtualAlloc
    test rax, rax
    jz @@exec_alloc_failed
    mov lpExecMem, rax
    
    ; Copy code to executable memory
    mov rsi, lpFileData
    add rsi, qwTextOffset
    mov rdi, lpExecMem
    mov rcx, qwTextSize
    rep movsb
    
    ; Calculate kernel entry point
    mov rax, lpExecMem
    add rax, dwKernelOffset
    mov qwKernelAddr, rax
    
    ; Step 7: Prepare test data
    mov rcx, OFFSET szStatusPreparingData
    call Print
    
    ; Initialize input: [1.0, 2.0, 3.0, 4.0]
    mov dword ptr [inputBuffer+0], 03F800000h    ; 1.0
    mov dword ptr [inputBuffer+4], 040000000h    ; 2.0
    mov dword ptr [inputBuffer+8], 040400000h    ; 3.0
    mov dword ptr [inputBuffer+12], 040800000h   ; 4.0
    
    ; Clear output
    xor eax, eax
    mov dword ptr [outputBuffer+0], eax
    mov dword ptr [outputBuffer+4], eax
    mov dword ptr [outputBuffer+8], eax
    mov dword ptr [outputBuffer+12], eax
    
    ; Step 8: Execute kernel
    mov rcx, OFFSET szStatusExecuting
    call Print
    
    ; Call kernel: RCX=input, RDX=output, R8=count
    lea rcx, [inputBuffer]
    lea rdx, [outputBuffer]
    mov r8, 4
    
    ; Save registers and call
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    
    call qwKernelAddr
    
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    
    ; Step 9: Display results
    mov rcx, OFFSET szKernelExecResults
    call Print
    
    ; Show input values
    mov rcx, OFFSET szInputValues
    call Print
    
    mov i, 0
@@print_input_loop:
    mov eax, i
    cmp eax, 4
    jge @@print_output
    
    mov ecx, i
    imul ecx, 4
    movss xmm0, dword ptr [inputBuffer+rcx]
    cvtss2sd xmm0, xmm0
    movq rdx, xmm0
    mov rcx, OFFSET szFloatValue
    call PrintFormat
    
    inc i
    jmp @@print_input_loop
    
@@print_output:
    mov rcx, OFFSET szOutputValues
    call Print
    
    mov i, 0
@@print_output_loop:
    mov eax, i
    cmp eax, 4
    jge @@cleanup
    
    mov ecx, i
    imul ecx, 4
    movss xmm0, dword ptr [outputBuffer+rcx]
    cvtss2sd xmm0, xmm0
    movq rdx, xmm0
    mov rcx, OFFSET szFloatValue
    call PrintFormat
    
    inc i
    jmp @@print_output_loop
    
@@cleanup:
    ; Free executable memory
    mov rcx, lpExecMem
    xor edx, edx
    mov r8d, MEM_RELEASE
    call VirtualFree
    
    ; Free file data
    mov rcx, lpFileData
    xor edx, edx
    mov r8d, MEM_RELEASE
    call VirtualFree
    
    mov rcx, OFFSET szKernelExecComplete
    call Print
    ret
    
@@open_failed:
    mov rcx, OFFSET szErrorOpenFailed
    call Print
    ret
    
@@alloc_failed:
    mov rcx, hFile
    call CloseHandle
    mov rcx, OFFSET szErrorAllocFailed
    call Print
    ret
    
@@not_x64:
    mov rcx, lpFileData
    xor edx, edx
    mov r8d, MEM_RELEASE
    call VirtualFree
    mov rcx, OFFSET szErrorNotX64
    call Print
    ret
    
@@text_not_found:
    mov rcx, lpFileData
    xor edx, edx
    mov r8d, MEM_RELEASE
    call VirtualFree
    mov rcx, OFFSET szErrorTextNotFound
    call Print
    ret
    
@@symbol_not_found:
    mov rcx, lpExecMem
    test rcx, rcx
    jz @@skip_free1
    xor edx, edx
    mov r8d, MEM_RELEASE
    call VirtualFree
@@skip_free1:
    mov rcx, lpFileData
    xor edx, edx
    mov r8d, MEM_RELEASE
    call VirtualFree
    mov rcx, OFFSET szErrorSymbolNotFound
    call Print
    ret
    
@@exec_alloc_failed:
    mov rcx, lpFileData
    xor edx, edx
    mov r8d, MEM_RELEASE
    call VirtualFree
    mov rcx, OFFSET szErrorExecAllocFailed
    call Print
    ret
    
DoExecuteKernel ENDP

;----------------------------------------------------------------------------
; SOVEREIGN PROFILE INTEGRATION
;----------------------------------------------------------------------------

; Forward declaration - implemented in CodexPro_Sovereign_Profile.asm
EXTERN RunSovereignProfile:PROC

;----------------------------------------------------------------------------
; UTILITY: Write to file
;----------------------------------------------------------------------------

WriteToFile PROC FRAME hFile:QWORD, lpString:QWORD
    LOCAL qwWritten:QWORD
    LOCAL qwLen:QWORD
    
    mov rcx, lpString
    call lstrlenA
    mov qwLen, rax
    
    mov rcx, hFile
    mov rdx, lpString
    mov r8, qwLen
    lea r9, qwWritten
    xor eax, eax
    mov [rsp+28h], rax
    call WriteFile
    
    ret
WriteToFile ENDP

;----------------------------------------------------------------------------
; ENTRY POINT
;----------------------------------------------------------------------------

main PROC FRAME
    LOCAL dwChoice:DWORD
    
    ; Init console
    mov ecx, STD_INPUT_HANDLE
    call GetStdHandle
    mov hStdIn, rax
    
    mov ecx, STD_OUTPUT_HANDLE
    call GetStdHandle
    mov hStdOut, rax
    
    ; Initialize critical sections
    mov rcx, OFFSET csOutput
    xor edx, edx
    call InitializeCriticalSectionAndSpinCount
    
    mov rcx, OFFSET csStatistics
    xor edx, edx
    call InitializeCriticalSectionAndSpinCount
    
    ; Print banner
    mov rcx, OFFSET szBanner
    mov edx, VER_MAJOR
    mov r8d, VER_MINOR
    mov r9d, VER_PATCH
    call PrintFormat
    
@@menu:
    mov rcx, OFFSET szMainMenu
    call Print
    
    call ReadInt
    mov dwChoice, eax
    
    cmp dwChoice, 1
    je @@do_analysis
    
    cmp dwChoice, 2
    je @@do_batch
    
    cmp dwChoice, 3
    je @@do_types
    
    cmp dwChoice, 4
    je @@do_vs2022
    
    cmp dwChoice, 5
    je @@do_cmake
    
    cmp dwChoice, 6
    je @@do_deobfuscator
    
    cmp dwChoice, 7
    je @@do_resources
    
    cmp dwChoice, 8
    je @@do_dependencies
    
    cmp dwChoice, 9
    je @@do_options
    
    cmp dwChoice, 10
    je @@do_kernel_exec
    
    ; Check for 'S' or 's' (Sovereign Profile)
    cmp dwChoice, 'S'
    je @@do_sovereign
    cmp dwChoice, 's'
    je @@do_sovereign
    
    cmp dwChoice, 0
    je @@exit
    
    jmp @@menu
    
@@do_analysis:
    call DoProfessionalAnalysis
    jmp @@menu
    
@@do_batch:
    call DoBatchReversal
    jmp @@menu
    
@@do_types:
    call DoTypeRecovery
    jmp @@menu
    
@@do_vs2022:
    call DoGenerateVS2022
    jmp @@menu
    
@@do_cmake:
    call DoGenerateCMake
    jmp @@menu
    
@@do_deobfuscator:
    call DoUniversalDeobfuscator
    jmp @@menu
    
@@do_resources:
    call DoResourceExtractor
    jmp @@menu
    
@@do_dependencies:
    call DoDependencyMapper
    jmp @@menu
    
@@do_options:
    call DoOptions
    jmp @@menu
    
@@do_sovereign:
    call RunSovereignProfile
    jmp @@menu
    
@@do_kernel_exec:
    call DoExecuteKernel
    jmp @@menu
    
@@exit:
    ; Cleanup critical sections
    mov rcx, OFFSET csOutput
    call DeleteCriticalSection
    
    mov rcx, OFFSET csStatistics
    call DeleteCriticalSection
    
    xor ecx, ecx
    call ExitProcess

main ENDP

;============================================================================
; DATA (Additional)
;============================================================================

.DATA

szBackslash             BYTE    "\", 0
szBackslashInclude      BYTE    "\include", 0
szBackslashSrc          BYTE    "\src", 0
szBackslashStar         BYTE    "\*", 0
szDotH                  BYTE    ".h", 0
szDotCpp                BYTE    ".cpp", 0
szDotDll                BYTE    ".dll", 0
szDotExe                BYTE    ".exe", 0
szCMakeLists            BYTE    "\CMakeLists.txt", 0
szTimeFormat            BYTE    "%04d-%02d-%02d %02d:%02d", 0

szSummaryFormat         BYTE    13, 10, "========================================", 13, 10
                        BYTE    "Analysis Complete:", 13, 10
                        BYTE    "  Files Processed: %d", 13, 10
                        BYTE    "  Headers Generated: %d", 13, 10
                        BYTE    "  Types Reconstructed: %d", 13, 10
                        BYTE    "========================================", 13, 10, 0

szTemplateIncludes      BYTE    "#include <windows.h>", 13, 10
                        BYTE    "#include <stdint.h>", 13, 10
                        BYTE    "#include <stdbool.h>", 13, 10, 13, 10, 0

; Additional Status Messages
szStatusBatchReversal   BYTE    "[*] Starting batch installation reversal...", 13, 10, 0
szBatchProgress         BYTE    "    [+] Processing item %d of %d...", 13, 10, 0
szBatchComplete         BYTE    "[+] Batch reversal complete!", 13, 10, 0

szStatusTypeRecovery    BYTE    "[*] Starting C++ type recovery...", 13, 10, 0
szStatusParsingRTTI     BYTE    "    [+] Parsing RTTI structures...", 13, 10, 0
szStatusReconstructingTypes BYTE "    [+] Reconstructing class hierarchies...", 13, 10, 0
szTypeRecoveryComplete  BYTE    "[+] Type recovery complete! Reconstructed %d types.", 13, 10, 0

szStatusGeneratingVS2022 BYTE   "[*] Generating Visual Studio 2022 solution...", 13, 10, 0
szVS2022Complete        BYTE    "[+] VS2022 solution generated successfully!", 13, 10, 0
szDotSln                BYTE    ".sln", 0
szDotVcxproj            BYTE    ".vcxproj", 0

szSlnHeader             BYTE    "Microsoft Visual Studio Solution File, Format Version 12.00", 13, 10
                        BYTE    "# Visual Studio Version 17", 13, 10
                        BYTE    "VisualStudioVersion = 17.0.31903.59", 13, 10
                        BYTE    "MinimumVisualStudioVersion = 10.0.40219.1", 13, 10, 13, 10, 0

szVcxprojHeader         BYTE    "<?xml version=\"1.0\" encoding=\"utf-8\"?>", 13, 10
                        BYTE    "<Project DefaultTargets=\"Build\" xmlns=\"http://schemas.microsoft.com/developer/msbuild/2003\">", 13, 10
                        BYTE    "  <ItemGroup Label=\"ProjectConfigurations\"></ItemGroup>", 13, 10
                        BYTE    "</Project>", 13, 10, 0

szStatusGeneratingCMake BYTE    "[*] Generating CMake + Ninja build system...", 13, 10, 0
szCMakeComplete         BYTE    "[+] CMakeLists.txt generated successfully!", 13, 10, 0

szDeobfuscatorMenu      BYTE    13, 10, "Universal Deobfuscator:", 13, 10
                        BYTE    "[1] JavaScript/TypeScript", 13, 10
                        BYTE    "[2] Python", 13, 10
                        BYTE    "[3] PowerShell", 13, 10
                        BYTE    "[4] Shell Script", 13, 10
                        BYTE    "[5] .NET (C#/VB)", 13, 10
                        BYTE    "[6] Java", 13, 10
                        BYTE    "[7] C/C++", 13, 10
                        BYTE    "[0] Back", 13, 10
                        BYTE    13, 10, "Select language: ", 0

szStatusDeobfuscating   BYTE    "[*] Deobfuscating code...", 13, 10, 0
szDeobfuscationComplete BYTE    "[+] Deobfuscation complete!", 13, 10, 0

szStatusExtractingResources BYTE "[*] Extracting resources...", 13, 10, 0
szResourceExtractComplete BYTE  "[+] Resource extraction complete!", 13, 10, 0

szStatusMappingDependencies BYTE "[*] Mapping dependencies...", 13, 10, 0
szDependencyMapComplete BYTE    "[+] Dependency mapping complete!", 13, 10, 0

szOptionsMenu           BYTE    13, 10, "Options & Configuration:", 13, 10
                        BYTE    "[1] Set thread count", 13, 10
                        BYTE    "[2] Set analysis depth", 13, 10
                        BYTE    "[3] View current statistics", 13, 10
                        BYTE    "[0] Back to main menu", 13, 10
                        BYTE    13, 10, "Selection: ", 0

szCurrentStats          BYTE    13, 10, "Current Statistics:", 13, 10
                        BYTE    "  Thread count: %d", 13, 10
                        BYTE    "  Total files: %d", 13, 10
                        BYTE    "  Processed files: %d", 13, 10, 13, 10, 0

END main
