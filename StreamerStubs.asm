; StreamerStubs.asm - Minimal stubs for streamer functions
; Provides basic implementations until full streamer is available

OPTION CASEMAP:NONE

.CODE

; ----------------------------------------------------------------
; STREAMER_INIT - Initialize streaming output
; Returns: rax = 0 (success)
; ----------------------------------------------------------------
STREAMER_INIT PROC EXPORT
    xor eax, eax        ; Return success
    ret
STREAMER_INIT ENDP

; ----------------------------------------------------------------
; STREAMER_PUSH_TOKEN - Push a token to output
; rcx = token_id
; Returns: rax = 0 (success)
; ----------------------------------------------------------------
STREAMER_PUSH_TOKEN PROC EXPORT
    ; TODO: Actually buffer the token
    xor eax, eax        ; Return success
    ret
STREAMER_PUSH_TOKEN ENDP

; ----------------------------------------------------------------
; STREAMER_FLUSH - Flush buffered tokens
; Returns: rax = 0 (success)
; ----------------------------------------------------------------
STREAMER_FLUSH PROC EXPORT
    ; TODO: Actually flush to output
    xor eax, eax        ; Return success
    ret
STREAMER_FLUSH ENDP

END
