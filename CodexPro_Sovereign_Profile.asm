;============================================================================
; CODEX PRO - SOVEREIGN PROFILE v1.0
; Specialized reverse engineering preset for RawrXD Sovereign kernels
;
; PURPOSE:
;   - Auto-detect Sovereign kernel naming conventions
;   - Generate C++ headers matching execution contract expectations
;   - Emit CMake/VS projects for MASM+C++ hybrid builds
;   - Reconstruct structs for telemetry, kernel descriptors, execution contexts
;
; TARGETS:
;   - Sovereign_*.obj/.lib files
;   - Execution backend integration headers
;   - Kernel dispatch tables and orchestrator glue
;============================================================================

OPTION WIN64:3
OPTION CASEMAP:NONE

;============================================================================
; INCLUDES
;============================================================================

INCLUDE \masm64\include64\win64.inc
INCLUDE \masm64\include64\kernel32.inc
INCLUDE \masm64\include64\shlwapi.inc

INCLUDELIB \masm64\lib64\kernel32.lib
INCLUDELIB \masm64\lib64\shlwapi.lib

;============================================================================
; SOVEREIGN-SPECIFIC CONSTANTS
;============================================================================

; Kernel Categories
SOVEREIGN_CAT_ATTENTION    EQU 1
SOVEREIGN_CAT_NORM         EQU 2
SOVEREIGN_CAT_GEMM         EQU 3
SOVEREIGN_CAT_FFN          EQU 4
SOVEREIGN_CAT_ROPE         EQU 5
SOVEREIGN_CAT_KV           EQU 6
SOVEREIGN_CAT_SAMPLER      EQU 7
SOVEREIGN_CAT_DEQUANT      EQU 8
SOVEREIGN_CAT_INFRA        EQU 9

; Naming Patterns
szPatternAttention         BYTE "Sovereign_Attention", 0
szPatternRMSNorm           BYTE "Sovereign_RMSNorm", 0
szPatternRoPE              BYTE "Sovereign_RoPE", 0
szPatternGEMM              BYTE "Sovereign_GEMM", 0
szPatternFFN               BYTE "Sovereign_FFN", 0
szPatternKV                BYTE "Sovereign_KV", 0
szPatternSampler           BYTE "Sovereign_Sampler", 0
szPatternDequant           BYTE "Sovereign_Dequant", 0
szPatternOrchestrator      BYTE "Sovereign_Orchestrator", 0

;============================================================================
; SOVEREIGN KERNEL SIGNATURES
;============================================================================

; Expected function signatures for each kernel type
SOVEREIGN_SIGNATURE STRUCT
    Category            DWORD ?
    FunctionPrefix      BYTE 64 DUP(?)
    ExpectedExports     DWORD ?
    HasAVX2             BYTE ?
    HasAVX512           BYTE ?
    HasAMX              BYTE ?
SOVEREIGN_SIGNATURE ENDS

; Predefined signatures
SIG_RMSNorm             SOVEREIGN_SIGNATURE <SOVEREIGN_CAT_NORM, "Sovereign_RMSNorm", 4, 1, 0, 0>
SIG_RoPE                SOVEREIGN_SIGNATURE <SOVEREIGN_CAT_ROPE, "Sovereign_RoPE", 3, 1, 0, 0>
SIG_Attention           SOVEREIGN_SIGNATURE <SOVEREIGN_CAT_ATTENTION, "Sovereign_Attention", 6, 1, 1, 0>
SIG_GEMM                SOVEREIGN_SIGNATURE <SOVEREIGN_CAT_GEMM, "Sovereign_GEMM", 8, 1, 1, 0>
SIG_FFN                 SOVEREIGN_SIGNATURE <SOVEREIGN_CAT_FFN, "Sovereign_FFN", 4, 1, 0, 0>

;============================================================================
; DATA SECTION
;============================================================================

.DATA

; Profile Banner
szSovereignBanner       BYTE "================================================================", 13, 10
                        BYTE "CODEX PRO - SOVEREIGN PROFILE v1.0", 13, 10
                        BYTE "RawrXD Kernel Analysis & Header Generation", 13, 10
                        BYTE "================================================================", 13, 10, 13, 10, 0

; Sovereign Menu
szSovereignMenu         BYTE "[1] Analyze Sovereign Kernel (Auto-detect type)", 13, 10
                        BYTE "[2] Generate Execution Contract Header", 13, 10
                        BYTE "[3] Generate Kernel Dispatch Table", 13, 10
                        BYTE "[4] Generate Orchestrator Glue Code", 13, 10
                        BYTE "[5] Generate CMake for MASM+C++ Hybrid", 13, 10
                        BYTE "[6] Validate Kernel Against Execution Backend", 13, 10
                        BYTE "[7] Batch Process All Sovereign Kernels", 13, 10
                        BYTE "[0] Back to Main Menu", 13, 10
                        BYTE 13, 10, "Selection: ", 0

; Status Messages
szStatusDetecting       BYTE "[*] Detecting Sovereign kernel type...", 13, 10, 0
szStatusDetected        BYTE "[+] Detected: %s (Category: %d)", 13, 10, 0
szStatusGenerating      BYTE "[*] Generating execution contract header...", 13, 10, 0
szStatusComplete        BYTE "[+] Generated: %s", 13, 10, 0

; Template: Execution Contract Header
szTemplateExecutionContract BYTE "// ============================================================================", 13, 10
                        BYTE "// Sovereign Execution Contract", 13, 10
                        BYTE "// Auto-generated by CodexPro Sovereign Profile", 13, 10
                        BYTE "// ============================================================================", 13, 10, 13, 10
                        BYTE "#pragma once", 13, 10, 13, 10
                        BYTE "#include <cstdint>", 13, 10
                        BYTE "#include <cstddef>", 13, 10, 13, 10
                        BYTE "// Kernel function signatures", 13, 10
                        BYTE "extern \"C\" {", 13, 10, 13, 10, 0

szTemplateExecutionContractEnd BYTE "}", 13, 10, 13, 10
                        BYTE "// Execution context structures", 13, 10
                        BYTE "struct SovereignExecutionContext {", 13, 10
                        BYTE "    void* kernel_buffer;", 13, 10
                        BYTE "    size_t buffer_size;", 13, 10
                        BYTE "    uint32_t flags;", 13, 10
                        BYTE "};", 13, 10, 0

; Template: Kernel Dispatch Table
szTemplateDispatchTable BYTE "// ============================================================================", 13, 10
                        BYTE "// Sovereign Kernel Dispatch Table", 13, 10
                        BYTE "// ============================================================================", 13, 10, 13, 10
                        BYTE "struct KernelDispatchEntry {", 13, 10
                        BYTE "    const char* name;", 13, 10
                        BYTE "    void* function_ptr;", 13, 10
                        BYTE "    uint32_t category;", 13, 10
                        BYTE "    uint32_t flags;", 13, 10
                        BYTE "};", 13, 10, 13, 10
                        BYTE "static const KernelDispatchEntry g_SovereignDispatchTable[] = {", 13, 10, 0

szTemplateDispatchEntry BYTE "    { \"%s\", (void*)%s, %d, 0 },", 13, 10, 0

szTemplateDispatchEnd   BYTE "};", 13, 10, 0

; Template: CMake for MASM+C++
szTemplateSovereignCMake BYTE "# Sovereign Kernel Build - MASM64 + C++ Hybrid", 13, 10
                        BYTE "cmake_minimum_required(VERSION 3.20)", 13, 10
                        BYTE "project(SovereignKernels VERSION 1.0.0 LANGUAGES C CXX ASM_MASM)", 13, 10, 13, 10
                        BYTE "# Enable MASM", 13, 10
                        BYTE "enable_language(ASM_MASM)", 13, 10, 13, 10
                        BYTE "# Find all MASM sources", 13, 10
                        BYTE "file(GLOB MASM_SOURCES \"src/asm/*.asm\")", 13, 10, 13, 10
                        BYTE "# Find all C++ glue", 13, 10
                        BYTE "file(GLOB CXX_SOURCES \"src/glue/*.cpp\")", 13, 10, 13, 10
                        BYTE "# Static library", 13, 10
                        BYTE "add_library(sovereign STATIC ${MASM_SOURCES} ${CXX_SOURCES})", 13, 10
                        BYTE "target_include_directories(sovereign PUBLIC include)", 13, 10
                        BYTE "# Link with execution backend", 13, 10
                        BYTE "target_link_libraries(sovereign PRIVATE execution)", 13, 10, 0

; Buffers
szKernelPath            BYTE MAX_PATH DUP(0)
szDetectedType          BYTE 64 DUP(0)
szOutputPath            BYTE MAX_PATH DUP(0)
szFunctionName          BYTE 128 DUP(0)

;============================================================================
; CODE SECTION
;============================================================================

.CODE

;----------------------------------------------------------------------------
; SOVEREIGN PROFILE ENTRY POINT
;----------------------------------------------------------------------------

RunSovereignProfile PROC FRAME
    LOCAL dwChoice:DWORD
    
    mov rcx, OFFSET szSovereignBanner
    call Print
    
@@menu:
    mov rcx, OFFSET szSovereignMenu
    call Print
    
    call ReadInt
    mov dwChoice, eax
    
    cmp dwChoice, 1
    je @@analyze_kernel
    
    cmp dwChoice, 2
    je @@generate_contract
    
    cmp dwChoice, 3
    je @@generate_dispatch
    
    cmp dwChoice, 4
    je @@generate_glue
    
    cmp dwChoice, 5
    je @@generate_cmake
    
    cmp dwChoice, 6
    je @@validate_kernel
    
    cmp dwChoice, 7
    je @@batch_process
    
    cmp dwChoice, 0
    je @@done
    
    jmp @@menu
    
@@analyze_kernel:
    call AnalyzeSovereignKernel
    jmp @@menu
    
@@generate_contract:
    call GenerateExecutionContract
    jmp @@menu
    
@@generate_dispatch:
    call GenerateDispatchTable
    jmp @@menu
    
@@generate_glue:
    call GenerateOrchestratorGlue
    jmp @@menu
    
@@generate_cmake:
    call GenerateSovereignCMake
    jmp @@menu
    
@@validate_kernel:
    call ValidateAgainstBackend
    jmp @@menu
    
@@batch_process:
    call BatchProcessSovereignKernels
    jmp @@menu
    
@@done:
    ret
RunSovereignProfile ENDP

;----------------------------------------------------------------------------
; ANALYZE SOVEREIGN KERNEL
;----------------------------------------------------------------------------

AnalyzeSovereignKernel PROC FRAME
    ; Get kernel path
    mov rcx, OFFSET szPromptInput
    call Print
    call ReadLine
    mov rcx, OFFSET szInputPath
    mov rdx, OFFSET szKernelPath
    call lstrcpyA
    
    mov rcx, OFFSET szStatusDetecting
    call Print
    
    ; Detect kernel type from filename
    mov rcx, OFFSET szKernelPath
    call DetectSovereignType
    
    ; Report detection
    mov rcx, OFFSET szStatusDetected
    mov rdx, OFFSET szDetectedType
    mov r8d, eax
    call PrintFormat
    
    ret
AnalyzeSovereignKernel ENDP

;----------------------------------------------------------------------------
; DETECT SOVEREIGN TYPE FROM FILENAME
; Returns: Category ID in EAX
;----------------------------------------------------------------------------

DetectSovereignType PROC FRAME lpPath:QWORD
    LOCAL dwCategory:DWORD
    
    mov dwCategory, 0
    
    ; Check for Attention
    mov rcx, lpPath
    mov rdx, OFFSET szPatternAttention
    call StrStrIA
    test rax, rax
    jz @@check_norm
    mov dwCategory, SOVEREIGN_CAT_ATTENTION
    mov rcx, OFFSET szDetectedType
    mov rdx, OFFSET szPatternAttention
    call lstrcpyA
    jmp @@done
    
@@check_norm:
    ; Check for RMSNorm
    mov rcx, lpPath
    mov rdx, OFFSET szPatternRMSNorm
    call StrStrIA
    test rax, rax
    jz @@check_rope
    mov dwCategory, SOVEREIGN_CAT_NORM
    mov rcx, OFFSET szDetectedType
    mov rdx, OFFSET szPatternRMSNorm
    call lstrcpyA
    jmp @@done
    
@@check_rope:
    ; Check for RoPE
    mov rcx, lpPath
    mov rdx, OFFSET szPatternRoPE
    call StrStrIA
    test rax, rax
    jz @@check_gemm
    mov dwCategory, SOVEREIGN_CAT_ROPE
    mov rcx, OFFSET szDetectedType
    mov rdx, OFFSET szPatternRoPE
    call lstrcpyA
    jmp @@done
    
@@check_gemm:
    ; Check for GEMM
    mov rcx, lpPath
    mov rdx, OFFSET szPatternGEMM
    call StrStrIA
    test rax, rax
    jz @@check_ffn
    mov dwCategory, SOVEREIGN_CAT_GEMM
    mov rcx, OFFSET szDetectedType
    mov rdx, OFFSET szPatternGEMM
    call lstrcpyA
    jmp @@done
    
@@check_ffn:
    ; Check for FFN
    mov rcx, lpPath
    mov rdx, OFFSET szPatternFFN
    call StrStrIA
    test rax, rax
    jz @@check_kv
    mov dwCategory, SOVEREIGN_CAT_FFN
    mov rcx, OFFSET szDetectedType
    mov rdx, OFFSET szPatternFFN
    call lstrcpyA
    jmp @@done
    
@@check_kv:
    ; Check for KV
    mov rcx, lpPath
    mov rdx, OFFSET szPatternKV
    call StrStrIA
    test rax, rax
    jz @@check_sampler
    mov dwCategory, SOVEREIGN_CAT_KV
    mov rcx, OFFSET szDetectedType
    mov rdx, OFFSET szPatternKV
    call lstrcpyA
    jmp @@done
    
@@check_sampler:
    ; Check for Sampler
    mov rcx, lpPath
    mov rdx, OFFSET szPatternSampler
    call StrStrIA
    test rax, rax
    jz @@check_dequant
    mov dwCategory, SOVEREIGN_CAT_SAMPLER
    mov rcx, OFFSET szDetectedType
    mov rdx, OFFSET szPatternSampler
    call lstrcpyA
    jmp @@done
    
@@check_dequant:
    ; Check for Dequant
    mov rcx, lpPath
    mov rdx, OFFSET szPatternDequant
    call StrStrIA
    test rax, rax
    jz @@unknown
    mov dwCategory, SOVEREIGN_CAT_DEQUANT
    mov rcx, OFFSET szDetectedType
    mov rdx, OFFSET szPatternDequant
    call lstrcpyA
    jmp @@done
    
@@unknown:
    mov dwCategory, SOVEREIGN_CAT_INFRA
    mov rcx, OFFSET szDetectedType
    mov rdx, OFFSET szPatternOrchestrator
    call lstrcpyA
    
@@done:
    mov eax, dwCategory
    ret
DetectSovereignType ENDP

;----------------------------------------------------------------------------
; GENERATE EXECUTION CONTRACT HEADER
;----------------------------------------------------------------------------

GenerateExecutionContract PROC FRAME
    LOCAL hFile:QWORD
    
    ; Get output path
    mov rcx, OFFSET szPromptOutput
    call Print
    call ReadLine
    mov rcx, OFFSET szInputPath
    mov rdx, OFFSET szOutputPath
    call lstrcpyA
    
    mov rcx, OFFSET szStatusGenerating
    call Print
    
    ; Create header file
    mov rcx, OFFSET szOutputPath
    mov rdx, OFFSET szBackslash
    call lstrcatA
    mov rcx, OFFSET szOutputPath
    mov rdx, OFFSET szDetectedType
    call lstrcatA
    mov rcx, OFFSET szOutputPath
    mov rdx, OFFSET szDotH
    call lstrcatA
    
    mov rcx, OFFSET szOutputPath
    xor edx, edx
    xor r8d, r8d
    xor r9d, r9d
    mov QWORD PTR [rsp+28h], CREATE_ALWAYS
    mov QWORD PTR [rsp+20h], FILE_ATTRIBUTE_NORMAL
    call CreateFileA
    cmp rax, INVALID_HANDLE_VALUE
    je @@error
    mov hFile, rax
    
    ; Write header
    mov rcx, hFile
    mov rdx, OFFSET szTemplateExecutionContract
    call WriteToFile
    
    ; Write detected function signatures
    mov rcx, hFile
    mov rdx, OFFSET szTemplateExecutionContractEnd
    call WriteToFile
    
    mov rcx, hFile
    call CloseHandle
    
    mov rcx, OFFSET szStatusComplete
    mov rdx, OFFSET szOutputPath
    call PrintFormat
    
@@error:
    ret
GenerateExecutionContract ENDP

;----------------------------------------------------------------------------
; GENERATE DISPATCH TABLE
;----------------------------------------------------------------------------

GenerateDispatchTable PROC FRAME
    LOCAL hFile:QWORD
    
    mov rcx, OFFSET szPromptOutput
    call Print
    call ReadLine
    mov rcx, OFFSET szInputPath
    mov rdx, OFFSET szOutputPath
    call lstrcpyA
    
    mov rcx, OFFSET szOutputPath
    mov rdx, OFFSET szBackslash
    call lstrcatA
    mov rcx, OFFSET szOutputPath
    mov rdx, OFFSET szDispatchTableName
    call lstrcatA
    
    mov rcx, OFFSET szOutputPath
    xor edx, edx
    xor r8d, r8d
    xor r9d, r9d
    mov QWORD PTR [rsp+28h], CREATE_ALWAYS
    mov QWORD PTR [rsp+20h], FILE_ATTRIBUTE_NORMAL
    call CreateFileA
    cmp rax, INVALID_HANDLE_VALUE
    je @@error
    mov hFile, rax
    
    mov rcx, hFile
    mov rdx, OFFSET szTemplateDispatchTable
    call WriteToFile
    
    ; Write entries for detected kernel
    mov rcx, OFFSET szTempBuffer
    mov rdx, OFFSET szTemplateDispatchEntry
    mov r8, OFFSET szDetectedType
    mov r9, OFFSET szDetectedType
    call wsprintfA
    
    mov rcx, hFile
    mov rdx, OFFSET szTempBuffer
    call WriteToFile
    
    mov rcx, hFile
    mov rdx, OFFSET szTemplateDispatchEnd
    call WriteToFile
    
    mov rcx, hFile
    call CloseHandle
    
@@error:
    ret
GenerateDispatchTable ENDP

;----------------------------------------------------------------------------
; PLACEHOLDER FUNCTIONS
;----------------------------------------------------------------------------

GenerateOrchestratorGlue PROC FRAME
    mov rcx, OFFSET szStatusGenerating
    call Print
    ; TODO: Generate C++ glue code
    ret
GenerateOrchestratorGlue ENDP

GenerateSovereignCMake PROC FRAME
    LOCAL hFile:QWORD
    
    mov rcx, OFFSET szPromptOutput
    call Print
    call ReadLine
    mov rcx, OFFSET szInputPath
    mov rdx, OFFSET szOutputPath
    call lstrcpyA
    
    mov rcx, OFFSET szOutputPath
    mov rdx, OFFSET szBackslash
    call lstrcatA
    mov rcx, OFFSET szOutputPath
    mov rdx, OFFSET szCMakeLists
    call lstrcatA
    
    mov rcx, OFFSET szOutputPath
    xor edx, edx
    xor r8d, r8d
    xor r9d, r9d
    mov QWORD PTR [rsp+28h], CREATE_ALWAYS
    mov QWORD PTR [rsp+20h], FILE_ATTRIBUTE_NORMAL
    call CreateFileA
    cmp rax, INVALID_HANDLE_VALUE
    je @@error
    mov hFile, rax
    
    mov rcx, hFile
    mov rdx, OFFSET szTemplateSovereignCMake
    call WriteToFile
    
    mov rcx, hFile
    call CloseHandle
    
    mov rcx, OFFSET szStatusComplete
    mov rdx, OFFSET szOutputPath
    call PrintFormat
    
@@error:
    ret
GenerateSovereignCMake ENDP

ValidateAgainstBackend PROC FRAME
    mov rcx, OFFSET szStatusValidating
    call Print
    ; TODO: Validate kernel exports against execution backend
    ret
ValidateAgainstBackend ENDP

BatchProcessSovereignKernels PROC FRAME
    mov rcx, OFFSET szStatusBatchProcessing
    call Print
    ; TODO: Process all Sovereign_*.obj files
    ret
BatchProcessSovereignKernels ENDP

;----------------------------------------------------------------------------
; UTILITY FUNCTIONS (from main CodexPro)
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

ReadInt PROC FRAME
    call ReadLine
    mov rcx, OFFSET szInputPath
    call atol
    ret
ReadInt ENDP

ReadLine PROC FRAME
    LOCAL qwRead:QWORD
    
    mov rcx, hStdIn
    mov rdx, OFFSET szInputPath
    mov r8d, MAX_PATH
    lea r9, qwRead
    call ReadConsoleA
    
    mov rax, qwRead
    cmp rax, 2
    jb @@done
    mov BYTE PTR [szInputPath+rax-2], 0
    
@@done:
    ret
ReadLine ENDP

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
; DATA (Additional)
;----------------------------------------------------------------------------

.DATA

szBackslash             BYTE "\", 0
szDotH                  BYTE ".h", 0
szCMakeLists            BYTE "\CMakeLists.txt", 0
szDispatchTableName     BYTE "SovereignDispatchTable.h", 0

szStatusValidating      BYTE "[*] Validating kernel against execution backend...", 13, 10, 0
szStatusBatchProcessing BYTE "[*] Batch processing all Sovereign kernels...", 13, 10, 0

END
