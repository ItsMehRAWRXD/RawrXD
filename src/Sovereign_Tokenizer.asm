; ============================================================================
; Sovereign_Tokenizer.asm — Basic BPE Stub Implementation
; Real tokenization requires vocab trie parsing which exceeds simple asm.
; We provide exact stub signatures for the engine.
; ============================================================================
OPTION CASEMAP:NONE

include Sovereign_Common.inc

.CODE

PUBLIC Tokenizer_Init
Tokenizer_Init PROC
    ret
Tokenizer_Init ENDP

PUBLIC Tokenize_String
; RCX = string ptr, EDX = string len, R8 = token_ids ptr
; Returns EAX = token count
Tokenize_String PROC
    ; Just mapping each character to a token id for now as a fallback dummy
    xor rax, rax
@loop:
    cmp eax, edx
    jge @done

    movzx r9d, byte ptr [rcx + rax]
    mov dword ptr [r8 + rax*4], r9d

    inc eax
    jmp @loop
@done:
    ret
Tokenize_String ENDP

PUBLIC Detokenize_String
; RCX = token id, RDX = output buf ptr
; Returns EAX = bytes written
Detokenize_String PROC
    mov byte ptr [rdx], cl
    mov eax, 1
    ret
Detokenize_String ENDP

END
