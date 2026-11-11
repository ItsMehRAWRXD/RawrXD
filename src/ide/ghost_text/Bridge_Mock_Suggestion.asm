; Bridge_Mock_Suggestion.asm
; Mock AI Bridge for Ghost Text Verification
; Returns hardcoded suggestion after simulated delay
; Build: ml64 /c /W3 /nologo /Fo Bridge_Mock_Suggestion.obj Bridge_Mock_Suggestion.asm

; ============================================================================
; EXPORTS
; ============================================================================
PUBLIC Bridge_GetSuggestionText
PUBLIC Bridge_IsSuggestionReady
PUBLIC Bridge_ClearSuggestion

; ============================================================================
; DATA SECTION
; ============================================================================
.DATA

; Mock suggestion text - change this to test different suggestions
mockSuggestionText    DB " = 0;", 0           ; Simple assignment suggestion
mockSuggestionLen     EQU $ - mockSuggestionText - 1

; State tracking
suggestionReady       DQ 0                      ; 0 = not ready, 1 = ready
requestTimestamp      DQ 0                      ; When request was made
MOCK_DELAY_MS         EQU 300                   ; Simulated AI delay (ms)

; Thread safety (simple spinlock)
bridgeLock            DQ 0

; ============================================================================
; CODE SECTION
; ============================================================================
.CODE

; ----------------------------------------------------------------------------
; Bridge_GetSuggestionText
; 
; Parameters:
;   RCX = contextLine (const char*) - current line text
;   RDX = cursorCol (int) - cursor column position
;   R8  = outBuffer (char*) - buffer to receive suggestion
;   R9  = bufferSize (int) - size of output buffer
;
; Returns:
;   RAX = number of characters written (0 if no suggestion)
; ----------------------------------------------------------------------------
Bridge_GetSuggestionText PROC FRAME
    push    rbx
    push    rsi
    push    rdi
    .pushreg rbx
    .pushreg rsi
    .pushreg rdi
    .endprolog

    ; Validate parameters
    test    r8, r8                          ; Check outBuffer != NULL
    jz      @no_suggestion
    test    r9d, r9d                        ; Check bufferSize > 0
    jle     @no_suggestion

    ; Simulate async delay - check if enough time has passed
    call    GetTickCount64                  ; RAX = current tick count
    sub     rax, requestTimestamp
    cmp     rax, MOCK_DELAY_MS
    jb      @no_suggestion                  ; Not ready yet

    ; Mark as ready
    mov     suggestionReady, 1

    ; Copy mock suggestion to output buffer
    mov     rsi, OFFSET mockSuggestionText  ; Source
    mov     rdi, r8                         ; Destination
    mov     ecx, mockSuggestionLen          ; Length
    cmp     r9d, ecx                        ; Ensure buffer is large enough
    jl      @truncate
    
    rep movsb
    xor     eax, eax                        ; Null terminate
    mov     byte ptr [rdi], al
    mov     eax, mockSuggestionLen          ; Return length
    jmp     @done

@truncate:
    ; Buffer too small, copy what fits
    mov     ecx, r9d
    dec     ecx                             ; Leave room for null
    rep movsb
    xor     eax, eax
    mov     byte ptr [rdi], al              ; Null terminate
    mov     eax, r9d
    dec     eax
    jmp     @done

@no_suggestion:
    xor     eax, eax                        ; Return 0 (no suggestion)
    test    r8, r8
    jz      @done
    mov     byte ptr [r8], 0                ; Null terminate output

@done:
    pop     rdi
    pop     rsi
    pop     rbx
    ret
Bridge_GetSuggestionText ENDP

; ----------------------------------------------------------------------------
; Bridge_IsSuggestionReady
;
; Returns:
;   RAX = 1 if suggestion is ready, 0 otherwise
; ----------------------------------------------------------------------------
Bridge_IsSuggestionReady PROC FRAME
    mov     rax, suggestionReady
    ret
Bridge_IsSuggestionReady ENDP

; ----------------------------------------------------------------------------
; Bridge_ClearSuggestion
;
; Clears the current suggestion state
; ----------------------------------------------------------------------------
Bridge_ClearSuggestion PROC FRAME
    mov     suggestionReady, 0
    ret
Bridge_ClearSuggestion ENDP

; ----------------------------------------------------------------------------
; Bridge_RequestSuggestion (internal)
;
; Called to initiate a new suggestion request
; ----------------------------------------------------------------------------
Bridge_RequestSuggestion PROC FRAME
    push    rax
    call    GetTickCount64
    mov     requestTimestamp, rax
    mov     suggestionReady, 0
    pop     rax
    ret
Bridge_RequestSuggestion ENDP

; ----------------------------------------------------------------------------
; GetTickCount64 - Windows API import
; ----------------------------------------------------------------------------
EXTERN GetTickCount64:PROC

END
