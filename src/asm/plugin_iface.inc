; =============================================================================
; plugin_iface.inc - RawrXD IDE Plugin Interface Definitions
; =============================================================================
; Shared ABI definitions for all pipeline modules. This header is included by
; both the host (win32ide_main.asm) and all plugin DLLs.
;
; Architecture:
;   - Each DLL exports a single GetVTable function
;   - Host calls GetVTable once after LoadLibrary
;   - All functions accessed via structure displacement
;   - O(1) function lookup, no string-based GetProcAddress per call
;
; Version: 1.0
; Date: 2026-06-18
; =============================================================================

; =============================================================================
; Common Types
; =============================================================================

; Boolean values (MASM doesn't have bool type)
FALSE               EQU 0
TRUE                EQU 1

; Common error codes
ERROR_SUCCESS       EQU 0
ERROR_INVALID_PARAM EQU 0xE0000001
ERROR_BUFFER_FULL   EQU 0xE0000002
ERROR_NOT_FOUND     EQU 0xE0000003
ERROR_OUT_OF_MEMORY EQU 0xE0000004
ERROR_NOT_INITIALIZED EQU 0xE0000005

; =============================================================================
; Editor Input Pipeline Interface
; =============================================================================

; Input event types
INPUT_EVENT_KEYDOWN     EQU 1
INPUT_EVENT_KEYUP       EQU 2
INPUT_EVENT_CHAR        EQU 3
INPUT_EVENT_MOUSEMOVE   EQU 4
INPUT_EVENT_MOUSEDOWN   EQU 5
INPUT_EVENT_MOUSEUP     EQU 6
INPUT_EVENT_SCROLL      EQU 7

; Key modifier flags
KEY_MOD_CTRL    EQU 0001h
KEY_MOD_SHIFT   EQU 0002h
KEY_MOD_ALT     EQU 0004h

; Input event structure (32 bytes)
INPUT_EVENT STRUCT
    eventType     DWORD ?        ; INPUT_EVENT_* type
    modifiers    DWORD ?        ; KEY_MOD_* flags
    keyCode      DWORD ?        ; Virtual key code
    charCode     DWORD ?        ; Unicode char (if INPUT_EVENT_CHAR)
    mouseX       DWORD ?        ; X coordinate
    mouseY       DWORD ?        ; Y coordinate
    mouseButton  DWORD ?        ; Left/Right/Middle
    timestamp    QWORD ?        ; GetTickCount64
INPUT_EVENT ENDS

; Editor pipeline vtable
EDITOR_PIPELINE_VTABLE STRUCT
    ; Initialization
    pfnInit              QWORD ? ; Editor_Init() -> BOOL
    pfnShutdown          QWORD ? ; Editor_Shutdown() -> void
    
    ; Input queue operations (SPSC lock-free)
    pfnPushInput         QWORD ? ; Editor_PushInput(INPUT_EVENT*) -> BOOL
    pfnPopInput          QWORD ? ; Editor_PopInput(INPUT_EVENT*) -> BOOL
    pfnPeekInput         QWORD ? ; Editor_PeekInput(INPUT_EVENT*) -> BOOL
    pfnGetInputCount     QWORD ? ; Editor_GetInputCount() -> DWORD
    
    ; Gap buffer operations
    pfnInsertChar        QWORD ? ; Editor_InsertChar(DWORD line, DWORD col, WCHAR ch) -> BOOL
    pfnDeleteChar       QWORD ? ; Editor_DeleteChar(DWORD line, DWORD col) -> BOOL
    pfnInsertLine       QWORD ? ; Editor_InsertLine(DWORD afterLine) -> BOOL
    pfnDeleteLine       QWORD ? ; Editor_DeleteLine(DWORD line) -> BOOL
    
    ; Cursor operations
    pfnGetCursorPos     QWORD ? ; Editor_GetCursorPos(DWORD* line, DWORD* col) -> void
    pfnSetCursorPos     QWORD ? ; Editor_SetCursorPos(DWORD line, DWORD col) -> void
    
    ; Buffer queries
    pfnGetLineCount     QWORD ? ; Editor_GetLineCount() -> DWORD
    pfnGetLineLength    QWORD ? ; Editor_GetLineLength(DWORD line) -> DWORD
    pfnGetLineText      QWORD ? ; Editor_GetLineText(DWORD line, WCHAR* buffer, DWORD* len) -> BOOL
    
    ; Statistics
    pfnGetStats         QWORD ? ; Editor_GetStats(DWORD* totalEvents, DWORD* droppedEvents) -> void
EDITOR_PIPELINE_VTABLE ENDS

; =============================================================================
; Debug Event Pipeline Interface
; =============================================================================

; Debug event types
DBG_EVENT_BREAKPOINT    EQU 1
DBG_EVENT_SINGLE_STEP   EQU 2
DBG_EVENT_EXCEPTION     EQU 3
DBG_EVENT_CREATE_PROCESS EQU 4
DBG_EVENT_EXIT_PROCESS  EQU 5
DBG_EVENT_CREATE_THREAD EQU 6
DBG_EVENT_EXIT_THREAD   EQU 7
DBG_EVENT_LOAD_DLL      EQU 8
DBG_EVENT_UNLOAD_DLL    EQU 9

; Debug state flags
DBG_STATE_HALTED        EQU 0001h
DBG_STATE_RUNNING       EQU 0002h
DBG_STATE_STEPPING      EQU 0004h
DBG_STATE_BREAKPOINT    EQU 0008h
DBG_STATE_EXCEPTION     EQU 0010h

; Debug event entry (512 bytes)
DEBUG_EVENT_ENTRY STRUCT
    eventType     DWORD ?        ; DBG_EVENT_* type
    processId     DWORD ?        ; Process ID
    threadId      DWORD ?        ; Thread ID
    _reserved     DWORD ?        ; Padding
    ; Register context (128 bytes)
    regRIP        QWORD ?
    regRSP        QWORD ?
    regRBP        QWORD ?
    regRAX        QWORD ?
    regRBX        QWORD ?
    regRCX        QWORD ?
    regRDX        QWORD ?
    regRSI        QWORD ?
    regRDI        QWORD ?
    regR8         QWORD ?
    regR9         QWORD ?
    regR10        QWORD ?
    regR11        QWORD ?
    regR12        QWORD ?
    regR13        QWORD ?
    regR14        QWORD ?
    regR15        QWORD ?
    regFlags      QWORD ?
    _regPadding   BYTE 40 dup(?)
    ; Timestamp
    timestamp     QWORD ?        ; GetTickCount64
    ; Stack frames (up to 16 frames, 8 bytes each = 128 bytes)
    stackFrames   QWORD 16 dup(?)
    frameCount    DWORD ?
    _framePadding BYTE 124 dup(?)
    ; Event-specific data (remaining bytes)
    eventData     BYTE 128 dup(?)
DEBUG_EVENT_ENTRY ENDS

; Breakpoint info
BREAKPOINT_INFO STRUCT
    address       QWORD ?        ; Breakpoint address
    bpType        DWORD ?        ; Type (software/hardware)
    enabled       DWORD ?        ; Enabled flag
    hitCount      QWORD ?        ; Hit count
BREAKPOINT_INFO ENDS

; Debug pipeline vtable
DEBUG_PIPELINE_VTABLE STRUCT
    ; Initialization
    pfnInit              QWORD ? ; DbgEvent_Init() -> BOOL
    pfnShutdown          QWORD ? ; DbgEvent_Shutdown() -> void
    
    ; Ring buffer operations (SPSC lock-free)
    pfnPushEvent         QWORD ? ; DbgEvent_Push(DEBUG_EVENT_ENTRY*) -> BOOL
    pfnPopEvent          QWORD ? ; DbgEvent_Pop(DEBUG_EVENT_ENTRY*) -> BOOL
    pfnPeekEvent         QWORD ? ; DbgEvent_Peek(DEBUG_EVENT_ENTRY*) -> BOOL
    pfnGetEventCount     QWORD ? ; DbgEvent_GetCount() -> DWORD
    
    ; Stack walking
    pfnWalkStack         QWORD ? ; DbgEvent_WalkStack(QWORD rip, QWORD rbp, QWORD* frames, DWORD maxFrames) -> DWORD
    
    ; Statistics
    pfnGetStats          QWORD ? ; DbgEvent_GetStats(DWORD* totalEvents, DWORD* droppedEvents) -> void
    pfnClear            QWORD ? ; DbgEvent_Clear() -> void
    
    ; IDE Bridge functions
    pfnDebugInit         QWORD ? ; IDE_DebugInit() -> BOOL
    pfnDebugPoll         QWORD ? ; IDE_DebugPoll() -> void
    pfnGetCurrentLine    QWORD ? ; IDE_DebugGetCurrentLine() -> DWORD
    pfnGetCurrentAddress QWORD ? ; IDE_DebugGetCurrentAddress() -> QWORD
    pfnGetState         QWORD ? ; IDE_DebugGetState() -> DWORD
    pfnGetCallStack     QWORD ? ; IDE_DebugGetCallStack(QWORD* frames, DWORD maxFrames) -> DWORD
    pfnSetBreakpoint    QWORD ? ; IDE_DebugSetBreakpoint(QWORD address) -> BOOL
    pfnClearBreakpoint  QWORD ? ; IDE_DebugClearBreakpoint(QWORD address) -> BOOL
    pfnGetBreakpoints   QWORD ? ; IDE_DebugGetBreakpoints(BREAKPOINT_INFO* buffer, DWORD maxCount) -> DWORD
    pfnContinue         QWORD ? ; IDE_DebugContinue() -> void
    pfnStep             QWORD ? ; IDE_DebugStep() -> void
    pfnStop             QWORD ? ; IDE_DebugStop() -> void
DEBUG_PIPELINE_VTABLE ENDS

; =============================================================================
; Syntax Highlighter Interface
; =============================================================================

; Token types
TOKEN_OPCODE        EQU 0     ; mov, add, sub, jmp, call, ret
TOKEN_REGISTER      EQU 1     ; rax, rbx, rcx, rdx, rsi, rdi, rsp, rbp, r8-r15
TOKEN_DIRECTIVE     EQU 2     ; .code, .data, .stack, .486, .model, .const
TOKEN_COMMENT       EQU 3     ; ; semicolon to EOL
TOKEN_STRING        EQU 4     ; "quoted strings"
TOKEN_NUMBER        EQU 5     ; 123, 0x1AF, 101010b
TOKEN_LABEL         EQU 6     ; label_name:
TOKEN_OPERATOR      EQU 7     ; +, -, *, /, [, ], <, >
TOKEN_WHITESPACE    EQU 8     ; spaces, tabs
TOKEN_IDENTIFIER    EQU 9     ; user-defined names
TOKEN_UNKNOWN       EQU 255   ; fallback

; Token entry (16 bytes)
TOKEN_ENTRY STRUCT
    startOffset    DWORD ?    ; Character offset in line
    tokenLength    DWORD ?    ; Token length (renamed from 'length' - reserved keyword)
    tokenType      BYTE ?     ; TOKEN_* type
    _reserved      BYTE 7 dup(?)
TOKEN_ENTRY ENDS

; Syntax highlighter vtable
SYNTAX_HIGHLIGHTER_VTABLE STRUCT
    ; Initialization
    pfnInit              QWORD ? ; Syntax_Init() -> BOOL
    pfnShutdown          QWORD ? ; Syntax_Shutdown() -> void
    
    ; Scanning operations
    pfnScanLine         QWORD ? ; Syntax_ScanLine(DWORD line, WCHAR* text, DWORD len) -> DWORD (token count)
    pfnScanAll          QWORD ? ; Syntax_ScanAll() -> void (full file scan)
    pfnInvalidateLine   QWORD ? ; Syntax_InvalidateLine(DWORD line) -> void
    
    ; Token queries
    pfnGetTokenAt       QWORD ? ; Syntax_GetTokenAt(DWORD line, DWORD col, TOKEN_ENTRY*) -> BOOL
    pfnGetLineTokens    QWORD ? ; Syntax_GetLineTokens(DWORD line, TOKEN_ENTRY* buffer, DWORD maxCount) -> DWORD
    
    ; Keyword tables
    pfnAddKeyword       QWORD ? ; Syntax_AddKeyword(WCHAR* keyword, BYTE tokenType) -> BOOL
    pfnLoadKeywords     QWORD ? ; Syntax_LoadKeywords(WCHAR* configPath) -> BOOL
    
    ; Statistics
    pfnGetStats         QWORD ? ; Syntax_GetStats(DWORD* totalTokens, DWORD* linesScanned) -> void
SYNTAX_HIGHLIGHTER_VTABLE ENDS

; =============================================================================
; LSP Bridge Interface
; =============================================================================

; LSP message types
LSP_MSG_REQUEST     EQU 1
LSP_MSG_RESPONSE    EQU 2
LSP_MSG_NOTIFICATION EQU 3

; LSP bridge vtable
LSP_BRIDGE_VTABLE STRUCT
    ; Initialization
    pfnInit              QWORD ? ; LSP_Init(WCHAR* serverPath) -> BOOL
    pfnShutdown          QWORD ? ; LSP_Shutdown() -> void
    
    ; Connection management
    pfnConnect          QWORD ? ; LSP_Connect() -> BOOL
    pfnDisconnect      QWORD ? ; LSP_Disconnect() -> void
    pfnIsConnected     QWORD ? ; LSP_IsConnected() -> BOOL
    
    ; Message operations
    pfnSendRequest     QWORD ? ; LSP_SendRequest(WCHAR* method, WCHAR* params, DWORD* id) -> BOOL
    pfnSendNotification QWORD ? ; LSP_SendNotification(WCHAR* method, WCHAR* params) -> BOOL
    pfnPollResponse    QWORD ? ; LSP_PollResponse(DWORD id, WCHAR* buffer, DWORD* len) -> BOOL
    
    ; Streaming lexer (extract specific fields without full JSON parse)
    pfnExtractField     QWORD ? ; LSP_ExtractField(WCHAR* json, WCHAR* fieldName, WCHAR* buffer, DWORD maxLen) -> BOOL
    
    ; Capabilities
    pfnGetCapabilities  QWORD ? ; LSP_GetCapabilities(WCHAR* buffer, DWORD maxLen) -> BOOL
LSP_BRIDGE_VTABLE ENDS

; =============================================================================
; Plugin Host Interface
; =============================================================================

; Plugin info structure
PLUGIN_INFO STRUCT
    pluginName     BYTE 64 dup(?)   ; Plugin name (null-terminated)
    version        DWORD ?          ; Version (major.minor.patch.build)
    apiVersion     DWORD ?          ; API version expected
    hModule         QWORD ?          ; HMODULE from LoadLibrary
    pVTable         QWORD ?          ; Pointer to vtable
PLUGIN_INFO ENDS

; Plugin host vtable (host -> plugin callbacks)
PLUGIN_HOST_VTABLE STRUCT
    ; Memory management
    pfnAlloc            QWORD ? ; Host_Alloc(SIZE_T size) -> void*
    pfnFree             QWORD ? ; Host_Free(void* ptr) -> void
    pfnRealloc          QWORD ? ; Host_Realloc(void* ptr, SIZE_T size) -> void*
    
    ; Logging
    pfnLog              QWORD ? ; Host_Log(DWORD level, WCHAR* message) -> void
    
    ; Event callbacks
    pfnOnEvent          QWORD ? ; Host_OnEvent(DWORD eventType, void* eventData) -> void
PLUGIN_HOST_VTABLE ENDS

; =============================================================================
; Version Information
; =============================================================================

; Current API version
PLUGIN_API_VERSION   EQU 00010000h  ; v1.0.0

; Plugin load flags
PLUGIN_LOAD_FLAG_NONE    EQU 0000h
PLUGIN_LOAD_FLAG_LAZY    EQU 0001h  ; Defer initialization
PLUGIN_LOAD_FLAG_HOT     EQU 0002h  ; Hot-reload enabled

; =============================================================================
; Macros for VTable Implementation
; =============================================================================

; Macro to define a vtable in .data section
; Usage: DEFINE_VTABLE MyVTable, MyInit, MyShutdown, ...
DEFINE_VTABLE MACRO vtableName, functions:VARARG
    .data
    vtableName STRUCT
    FOR func, <&functions>
        pfn&func QWORD ?
    ENDM
    vtableName ENDS
ENDM

; Macro to initialize a vtable with function pointers
; Usage: INIT_VTABLE g_MyVTable, MyInit, MyShutdown, ...
INIT_VTABLE MACRO vtableName, functions:VARARG
    vtableName LABEL QWORD
    FOR func, <&functions>
        DQ func
    ENDM
ENDM

; =============================================================================
; End of Interface Definitions
; =============================================================================
