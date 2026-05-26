; ============================================================================
; Sovereign_Common.inc — Architectural Interface Definitions
; Zero dependencies. x64 MASM only. No stubs.
; ============================================================================

OPTION CASEMAP:NONE

; ----------------------------------------------------------------------------
; GGUF Format Constants
; ----------------------------------------------------------------------------
GGUF_MAGIC             equ 046554747h
GGUF_VERSION           equ 3
GGUF_DEFAULT_ALIGNMENT equ 32

GGML_TYPE_F32          equ 0
GGML_TYPE_F16          equ 1
GGML_TYPE_Q4_0         equ 2
GGML_TYPE_Q4_1         equ 3
GGML_TYPE_Q5_0         equ 6
GGML_TYPE_Q5_1         equ 7
GGML_TYPE_Q8_0         equ 8

; ----------------------------------------------------------------------------
; Windows API Constants
; ----------------------------------------------------------------------------
GENERIC_READ           equ 080000000h
FILE_SHARE_READ        equ 000000001h
OPEN_EXISTING          equ 3
FILE_ATTRIBUTE_NORMAL  equ 000000080h
PAGE_READONLY          equ 02h
FILE_MAP_READ          equ 000000004h
STD_OUTPUT_HANDLE      equ -11
STD_ERROR_HANDLE       equ -12
INVALID_HANDLE_VALUE   equ -1
MEM_COMMIT             equ 00001000h
MEM_RESERVE            equ 00002000h
MEM_RELEASE            equ 00008000h
PAGE_READWRITE         equ 04h

; ============================================================================
; Sovereign_Common.inc — Architectural Interface Definitions
; Zero dependencies. x64 MASM only. No stubs.
; ============================================================================

OPTION CASEMAP:NONE

; ----------------------------------------------------------------------------
; GGUF Format Constants
; ----------------------------------------------------------------------------
GGUF_MAGIC             equ 046554747h
GGUF_VERSION           equ 3
GGUF_DEFAULT_ALIGNMENT equ 32

GGML_TYPE_F32          equ 0
GGML_TYPE_F16          equ 1
GGML_TYPE_Q4_0         equ 2
GGML_TYPE_Q4_1         equ 3
GGML_TYPE_Q5_0         equ 6
GGML_TYPE_Q5_1         equ 7
GGML_TYPE_Q8_0         equ 8

; ----------------------------------------------------------------------------
; Windows API Constants
; ----------------------------------------------------------------------------
GENERIC_READ           equ 080000000h
FILE_SHARE_READ        equ 000000001h
OPEN_EXISTING          equ 3
FILE_ATTRIBUTE_NORMAL  equ 000000080h
PAGE_READONLY          equ 02h
FILE_MAP_READ          equ 000000004h
STD_OUTPUT_HANDLE      equ -11
STD_ERROR_HANDLE       equ -12
INVALID_HANDLE_VALUE   equ -1
MEM_COMMIT             equ 00001000h
MEM_RESERVE            equ 00002000h
MEM_RELEASE            equ 00008000h
PAGE_READWRITE         equ 04h

; ----------------------------------------------------------------------------
; API Table Structure
; ----------------------------------------------------------------------------
SOVEREIGN_API_TABLE STRUCT
    pLoadLibraryA       dq ?
    pGetProcAddress     dq ?
    pVirtualAlloc       dq ?
    pVirtualFree        dq ?
    pVirtualLock        dq ?
    pCreateFileA        dq ?
    pCreateFileW        dq ?
    pReadFile           dq ?
    pWriteFile          dq ?
    pSetFilePointerEx   dq ?
    pGetFileSizeEx      dq ?
    pCloseHandle        dq ?
    pCreateFileMappingA dq ?
    pMapViewOfFile      dq ?
    pUnmapViewOfFile    dq ?
    pGetStdHandle       dq ?
    pExitProcess        dq ?
    pFlushViewOfFile    dq ?
    pGetTickCount64     dq ?
SOVEREIGN_API_TABLE ENDS

; ----------------------------------------------------------------------------
; Model State
; ----------------------------------------------------------------------------
MODEL_STATE STRUCT
    magic               dd ?
    version             dd ?
    tensor_count        dq ?
    metadata_kv_count   dq ?
    pTensorTable        dq ?
    pMetadata           dq ?
    pWeightBase         dq ?
    weight_size         dq ?
    vocab_size          dd ?
    n_layers            dd ?
    n_heads             dd ?
    n_kv_heads          dd ?
    n_embd              dd ?
    n_rotary            dd ?
    ftype               dd ?
    file_handle         dq ?
    map_handle          dq ?
    pIndex              dq ?
MODEL_STATE ENDS

; ----------------------------------------------------------------------------
; Dispatcher Table
; ----------------------------------------------------------------------------
DISPATCH_TABLE STRUCT
    pGemv_F32           dq ?
    pGemv_Q4_0          dq ?
    pGemv_Q8_0          dq ?
    pDequant_Q4_0       dq ?
    pDequant_Q8_0       dq ?
    pSoftmax            dq ?
    pSilu               dq ?
    pRope               dq ?
DISPATCH_TABLE ENDS

; ----------------------------------------------------------------------------
; Governance State
; ----------------------------------------------------------------------------
GOV_STATE STRUCT
    status              dd ?
    current_layer       dd ?
    current_token       dd ?
    token_count         dd ?
    error_code          dd ?
    bytes_written       dd ?
    pModelState         dq ?
    pKVCache            dq ?
    pTokenBuffer        dq ?
    dispatch_table      DISPATCH_TABLE <>
    pLogits             dq ?
    kv_cache_pos        dq ?
    kv_cache_size       dq ?
    temperature         dd ?
    top_k               dd ?
    top_p               dd ?
    repetition_penalty  dd ?
    pad_1               dd ?
GOV_STATE ENDS

; ----------------------------------------------------------------------------
; Tensor Info (GGUF v3)
; ----------------------------------------------------------------------------
TENSOR_INFO STRUCT
    name_len            dq ?
    pName               dq ?
    name_hash           dq ?
    n_dims              dd ?
    align_0             dd ?
    tensor_ne           dq 4 dup(?)
    tensor_type         dd ?
    align_1             dd ?
    tensor_offset       dq ?
    pData               dq ?
TENSOR_INFO ENDS

; ----------------------------------------------------------------------------
; External Symbols
; ----------------------------------------------------------------------------
EXTERNDEF g_ApiTable : SOVEREIGN_API_TABLE
EXTERNDEF g_pGov : QWORD
EXTERNDEF g_HeapBase : QWORD
EXTERNDEF g_HeapPtr : QWORD
EXTERNDEF g_HeapLimit : QWORD
EXTERNDEF g_DbgMallocRet     : QWORD
EXTERNDEF g_DbgLoaderR13     : QWORD
EXTERNDEF g_DbgPIdxFieldAddr : QWORD
EXTERNDEF g_DbgPIdxReadback  : QWORD
EXTERNDEF g_DbgTocPIdx       : QWORD

; ----------------------------------------------------------------------------
; TitanContext (Legacy Support for some components)
; ----------------------------------------------------------------------------
TC_PeakCycles      EQU 0
TC_CurrentClock    EQU 8
TC_AuditCount      EQU 16
TC_StatusFlags     EQU 24
TC_HubPtr          EQU 32

; ----------------------------------------------------------------------------
; External Symbols
; ----------------------------------------------------------------------------
EXTERNDEF g_ApiTable : SOVEREIGN_API_TABLE
EXTERNDEF g_pGov : QWORD
EXTERNDEF g_HeapBase : QWORD
EXTERNDEF g_HeapPtr : QWORD
EXTERNDEF g_HeapLimit : QWORD
