;======================================================================
; model_router.asm - Model selection, modes, and single-fallback policy
;======================================================================
INCLUDE windows.inc

.CONST
MODE_FLAG_MAX           EQU 1
MODE_FLAG_SEARCH_WEB    EQU 2
MODE_FLAG_TURBO         EQU 4
MODE_FLAG_AUTO_INSTANT  EQU 8
MODE_FLAG_LEGACY        EQU 16
MODE_FLAG_THINKING_STD  EQU 32

.DATA?
g_modeFlags            DWORD 0
g_primaryModelName     DB "gpt-4",0
g_fallbackModelName    DB "gpt-3.5-turbo",0
g_modelCallInProgress  DWORD 0
g_fallbackPolicy       DWORD 1    ; 1 = allow fallback on error
g_lastResponsePtr      QWORD ?
BUSY_ERR               DB '{"error":"Busy"}',0
JSON_BODY_FMT          DB '{"model":"%s","messages":[{"role":"user","content":"%s"}],"max_tokens":%d,"stream":true}',0

.CODE

ModelRouter_SetMode PROC flags:DWORD
    mov dword ptr g_modeFlags, ecx
    ret
ModelRouter_SetMode ENDP

ModelRouter_GetMode PROC
    mov eax, dword ptr g_modeFlags
    ret
ModelRouter_GetMode ENDP

ModelRouter_SetFallbackPolicy PROC allow:DWORD
    mov dword ptr g_fallbackPolicy, ecx
    ret
ModelRouter_SetFallbackPolicy ENDP

; Main entry: Call model with prompt, type (e.g., "chat"/"planning"), maxTokens
ModelRouter_CallModel PROC pPrompt:QWORD, pType:QWORD, maxTokens:DWORD
    LOCAL pJsonBody:QWORD
    LOCAL cbJsonBody:DWORD
    LOCAL pModelName:QWORD
    LOCAL tryPrimary:DWORD
    LOCAL tryFallback:DWORD
    LOCAL result:DWORD

    ; Prevent concurrent model calls (simple guard)
    mov eax, dword ptr g_modelCallInProgress
    .if eax != 0
        ; another call in progress
        lea rax, BUSY_ERR
        ret
    .endif
    mov dword ptr g_modelCallInProgress, 1

    ; Choose model based on flags
    mov eax, dword ptr g_modeFlags
    test eax, MODE_FLAG_MAX
    jz .Lnot_max
    lea rax, g_primaryModelName
    mov pModelName, rax
    jmp .Lmodel_chosen
.Lnot_max:
    ; Default primary
    lea rax, g_primaryModelName
    mov pModelName, rax
.Lmodel_chosen:

    ; Build JSON request body (simple layout)
    invoke GetProcessHeap
    mov rcx, rax
    mov rdx, HEAP_ZERO_MEMORY
    mov r8d, 8192
    call HeapAlloc
    mov pJsonBody, rax

    lea rcx, pJsonBody
    lea rdx, JSON_BODY_FMT
    mov r8, pModelName
    mov r9, pPrompt
    push maxTokens
    call wsprintfA
    add rsp, 8

    ; Send request (primary)
    ; Start call session (accumulate tokens into call buffer)
    mov rcx, pModelName
    call ChatStreamManager_StartCall

    ; Call CopilotHttp_SendChatRequest(pJsonBody, lstrlenA(pJsonBody))
    mov rcx, pJsonBody
    call lstrlenA
    mov rdx, rax
    call CopilotHttp_SendChatRequest
    test rax, rax
    .if rax == 0
        ; Primary failed - discard any collected tokens and optionally fallback
        mov rcx, 0
        call ChatStreamManager_FinishCall
        test dword ptr g_fallbackPolicy, 1
        jz .Ldone
        ; Try fallback once (clear and start new call session)
        lea rcx, g_fallbackModelName
        mov pModelName, rcx
        ; rebuild body with fallback model
        lea rcx, pJsonBody
        lea rdx, JSON_BODY_FMT
        mov r8, pModelName
        mov r9, pPrompt
        push maxTokens
        call wsprintfA
        add rsp, 8
        mov rcx, pModelName
        call ChatStreamManager_StartCall
        mov rcx, pJsonBody
        call lstrlenA
        mov rdx, rax
        call CopilotHttp_SendChatRequest
        test rax, rax
        jz .Ldone
    .endif
    ; On success finish call and keep tokens
    mov rcx, 1
    call ChatStreamManager_FinishCall

    ; On success, set last response pointer to pJsonBody for consumer; in real impl
    ; the response would be streamed via ChatStream_OnToken and collected
    mov qword ptr g_lastResponsePtr, pJsonBody
    mov result, 1
    jmp .Lcleanup

.Ldone:
    mov result, 0

.Lcleanup:
    mov dword ptr g_modelCallInProgress, 0
    mov eax, result
    ret
ModelRouter_CallModel ENDP

END