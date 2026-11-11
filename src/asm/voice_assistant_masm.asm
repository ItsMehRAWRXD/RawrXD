; voice_assistant_masm.asm - MASM x64 integration with Voice Assistant RAG
; Demonstrates calling C API from pure assembly
; ============================================================================

; External C functions from voice_assistant_masm_bridge
EXTERN VoiceAssistant_CreateManager:PROC
EXTERN VoiceAssistant_DestroyManager:PROC
EXTERN VoiceAssistant_QueryCodebase:PROC
EXTERN VoiceAssistant_ProcessVoiceInput:PROC
EXTERN VoiceAssistant_CreateSession:PROC
EXTERN VoiceAssistant_EndSession:PROC
EXTERN VoiceAssistant_DispatchIDEAction:PROC
EXTERN VoiceAssistant_HasIDEAction:PROC
EXTERN VoiceAssistant_JsonGetString:PROC
EXTERN VoiceAssistant_JsonGetInt:PROC
EXTERN VoiceAssistant_JsonGetArraySize:PROC
EXTERN VoiceAssistant_FreeJson:PROC
EXTERN VoiceAssistant_FreeString:PROC
EXTERN VoiceAssistant_GetLastError:PROC
EXTERN VoiceAssistant_IsReady:PROC
EXTERN VoiceAssistant_SetContextAnalyzer:PROC

; Windows API functions
EXTERN GetStdHandle:PROC
EXTERN WriteConsoleA:PROC
EXTERN ExitProcess:PROC
EXTERN LoadLibraryA:PROC
EXTERN GetProcAddress:PROC

; ============================================================================
; Data Section
; ============================================================================

.data

; String constants
szVoiceBridgeDll    BYTE "voice_assistant_masm_bridge.dll", 0
szCreateManager     BYTE "VoiceAssistant_CreateManager", 0
szQueryCodebase     BYTE "VoiceAssistant_QueryCodebase", 0
szProcessVoice      BYTE "VoiceAssistant_ProcessVoiceInput", 0
szFreeJson          BYTE "VoiceAssistant_FreeJson", 0
szFreeString        BYTE "VoiceAssistant_FreeString", 0

; Query strings
szQueryFunctions    BYTE "find all functions", 0
szQueryClasses      BYTE "explain this class", 0
szCurrentFile       BYTE "src/main.cpp", 0
szAssistantType     BYTE "hybrid", 0
szSessionId         BYTE "", 0

; Intent strings
szIntentBuild       BYTE "ide_build", 0
szIntentRun         BYTE "ide_run", 0
szIntentDebug       BYTE "ide_debug", 0

; Output buffers
jsonBuffer          BYTE 4096 DUP(0)
errorBuffer         BYTE 1024 DUP(0)
sessionIdBuffer     BYTE 256 DUP(0)

; Handles
hManager            QWORD 0
hJsonResponse       QWORD 0
hStdOut             QWORD 0

; ============================================================================
; Code Section
; ============================================================================

.code

; ----------------------------------------------------------------------------
; Main entry point for demonstration
; ----------------------------------------------------------------------------
main PROC
    ; Initialize console output
    sub     rsp, 40                 ; Shadow space + alignment
    
    ; Get stdout handle
    mov     rcx, -11                ; STD_OUTPUT_HANDLE
    call    GetStdHandle
    mov     hStdOut, rax
    
    ; Print header
    lea     rcx, msgHeader
    call    PrintString
    
    ; Initialize Voice Assistant Manager
    call    InitializeVoiceAssistant
    test    rax, rax
    jz      init_failed
    
    mov     hManager, rax
    
    ; Run RAG query
    call    DemoRAGQuery
    
    ; Run voice input processing
    call    DemoVoiceInput
    
    ; Run IDE action dispatch
    call    DemoIDEActions
    
    ; Cleanup
    mov     rcx, hManager
    call    VoiceAssistant_DestroyManager
    
    ; Print success
    lea     rcx, msgSuccess
    call    PrintString
    
    xor     ecx, ecx                ; Exit code 0
    call    ExitProcess
    
init_failed:
    ; Get and print error
    lea     rcx, errorBuffer
    mov     rdx, 1024
    call    VoiceAssistant_GetLastError
    
    lea     rcx, msgInitFailed
    call    PrintString
    
    lea     rcx, errorBuffer
    call    PrintString
    
    mov     ecx, 1                  ; Exit code 1
    call    ExitProcess

main ENDP

; ----------------------------------------------------------------------------
; InitializeVoiceAssistant
; Returns: Manager handle in RAX, or 0 on failure
; ----------------------------------------------------------------------------
InitializeVoiceAssistant PROC
    sub     rsp, 40
    
    ; Create manager
    call    VoiceAssistant_CreateManager
    test    rax, rax
    jz      init_fail
    
    mov     hManager, rax
    
    ; Set context analyzer (optional)
    mov     rcx, rax                  ; Manager handle
    lea     rdx, szCurrentFile      ; Path (can be NULL)
    call    VoiceAssistant_SetContextAnalyzer
    
    ; Check if ready
    mov     rcx, hManager
    call    VoiceAssistant_IsReady
    test    rax, rax
    jz      init_fail
    
    mov     rax, hManager
    add     rsp, 40
    ret
    
init_fail:
    xor     rax, rax
    add     rsp, 40
    ret
InitializeVoiceAssistant ENDP

; ----------------------------------------------------------------------------
; DemoRAGQuery
; Demonstrates semantic code query
; ----------------------------------------------------------------------------
DemoRAGQuery PROC
    sub     rsp, 56                 ; Shadow space + alignment + local vars
    
    ; Print section header
    lea     rcx, msgRAGQuery
    call    PrintString
    
    ; Execute RAG query
    mov     rcx, hManager
    lea     rdx, szQueryFunctions
    lea     r8, szCurrentFile
    mov     r9d, 42                 ; Line number
    call    VoiceAssistant_QueryCodebase
    
    test    rax, rax
    jz      query_failed
    
    mov     hJsonResponse, rax
    
    ; Get status from JSON
    mov     rcx, rax
    lea     rdx, szKeyStatus
    lea     r8, jsonBuffer
    mov     r9, 4096
    call    VoiceAssistant_JsonGetString
    
    ; Print status
    lea     rcx, msgStatus
    call    PrintString
    lea     rcx, jsonBuffer
    call    PrintString
    call    PrintNewline
    
    ; Get result count
    mov     rcx, hJsonResponse
    lea     rdx, szKeyResultCount
    lea     r8, [rsp+48]           ; Local int storage
    call    VoiceAssistant_JsonGetInt
    
    ; Print result count
    lea     rcx, msgResultCount
    call    PrintString
    ; (Would convert int to string here)
    call    PrintNewline
    
    ; Free JSON response
    mov     rcx, hJsonResponse
    call    VoiceAssistant_FreeJson
    
    add     rsp, 56
    ret
    
query_failed:
    lea     rcx, msgQueryFailed
    call    PrintString
    
    add     rsp, 56
    ret
DemoRAGQuery ENDP

; ----------------------------------------------------------------------------
; DemoVoiceInput
; Demonstrates voice input processing
; ----------------------------------------------------------------------------
DemoVoiceInput PROC
    sub     rsp, 56
    
    ; Print section header
    lea     rcx, msgVoiceInput
    call    PrintString
    
    ; Process voice input
    mov     rcx, hManager
    lea     rdx, szQueryFunctions
    lea     r8, szAssistantType
    lea     r9, szSessionId
    call    VoiceAssistant_ProcessVoiceInput
    
    test    rax, rax
    jz      voice_failed
    
    mov     hJsonResponse, rax
    
    ; Get assistant response
    mov     rcx, rax
    lea     rdx, szKeyResponse
    lea     r8, jsonBuffer
    mov     r9, 4096
    call    VoiceAssistant_JsonGetString
    
    ; Print response
    lea     rcx, msgAssistantResponse
    call    PrintString
    lea     rcx, jsonBuffer
    call    PrintString
    call    PrintNewline
    
    ; Free JSON
    mov     rcx, hJsonResponse
    call    VoiceAssistant_FreeJson
    
    add     rsp, 56
    ret
    
voice_failed:
    lea     rcx, msgVoiceFailed
    call    PrintString
    
    add     rsp, 56
    ret
DemoVoiceInput ENDP

; ----------------------------------------------------------------------------
; DemoIDEActions
; Demonstrates IDE action dispatch
; ----------------------------------------------------------------------------
DemoIDEActions PROC
    sub     rsp, 40
    
    ; Print section header
    lea     rcx, msgIDEActions
    call    PrintString
    
    ; Check if build action is available
    mov     rcx, hManager
    lea     rdx, szIntentBuild
    call    VoiceAssistant_HasIDEAction
    
    test    rax, rax
    jz      no_build_action
    
    ; Dispatch build action
    mov     rcx, hManager
    lea     rdx, szIntentBuild
    call    VoiceAssistant_DispatchIDEAction
    
    test    rax, rax
    jz      dispatch_failed
    
    mov     hJsonResponse, rax
    
    ; Get command ID
    mov     rcx, rax
    lea     rdx, szKeyCommandId
    lea     r8, jsonBuffer
    mov     r9, 4096
    call    VoiceAssistant_JsonGetString
    
    ; Print dispatched command
    lea     rcx, msgDispatched
    call    PrintString
    lea     rcx, jsonBuffer
    call    PrintString
    call    PrintNewline
    
    ; Free JSON
    mov     rcx, hJsonResponse
    call    VoiceAssistant_FreeJson
    
dispatch_failed:
no_build_action:
    add     rsp, 40
    ret
DemoIDEActions ENDP

; ----------------------------------------------------------------------------
; PrintString
; Parameters: RCX = pointer to null-terminated string
; ----------------------------------------------------------------------------
PrintString PROC
    sub     rsp, 40
    
    ; Calculate string length
    mov     rdx, rcx                ; Save string pointer
    xor     r8, r8                  ; Length counter
    
count_loop:
    mov     al, [rdx + r8]
    test    al, al
    jz      print_it
    inc     r8
    jmp     count_loop
    
print_it:
    ; WriteConsoleA(hStdOut, string, length, NULL, NULL)
    mov     rcx, hStdOut
    ; RDX already has string pointer
    ; R8 already has length
    xor     r9, r9                  ; lpNumberOfCharsWritten (optional)
    mov     qword ptr [rsp+32], 0   ; lpReserved
    call    WriteConsoleA
    
    add     rsp, 40
    ret
PrintString ENDP

; ----------------------------------------------------------------------------
; PrintNewline
; ----------------------------------------------------------------------------
PrintNewline PROC
    sub     rsp, 40
    lea     rcx, szNewline
    call    PrintString
    add     rsp, 40
    ret
PrintNewline ENDP

; ============================================================================
; String Constants
; ============================================================================

.data

msgHeader           BYTE "=== RawrXD Voice Assistant RAG Demo ===", 13, 10, 0
msgRAGQuery         BYTE 13, 10, "[RAG Query]", 13, 10, 0
msgVoiceInput       BYTE 13, 10, "[Voice Input]", 13, 10, 0
msgIDEActions       BYTE 13, 10, "[IDE Actions]", 13, 10, 0
msgStatus           BYTE "Status: ", 0
msgResultCount      BYTE "Results: ", 0
msgAssistantResponse BYTE "Assistant: ", 0
msgDispatched       BYTE "Dispatched: ", 0
msgSuccess          BYTE 13, 10, "=== Demo Complete ===", 13, 10, 0
msgInitFailed       BYTE "Failed to initialize: ", 0
msgQueryFailed      BYTE "Query failed", 13, 10, 0
msgVoiceFailed      BYTE "Voice processing failed", 13, 10, 0
szNewline           BYTE 13, 10, 0

; JSON keys
szKeyStatus         BYTE "status", 0
szKeyResultCount    BYTE "result_count", 0
szKeyResponse       BYTE "response", 0
szKeyCommandId      BYTE "command_id", 0

; ============================================================================
; End of Assembly
; ============================================================================

END

