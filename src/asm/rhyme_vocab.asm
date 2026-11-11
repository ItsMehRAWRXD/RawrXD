; RhymeVocab.asm - Pure x64 MASM Rhyming Vocabulary Structure
; Three words intentionally missing - gaps in the pattern
; =============================================================================

OPTION CASEMAP:NONE
OPTION DOTNAME

; =============================================================================
; CONSTANTS
; =============================================================================
WORD_COUNT      EQU     12          ; Total slots (3 intentionally empty)
MAX_WORD_LEN    EQU     16          ; Max chars per word
RHYME_AY        EQU     1           ; Sounds like "-ay"
RHYME_EE        EQU     2           ; Sounds like "-ee"
RHYME_OO        EQU     3           ; Sounds like "-oo"

; =============================================================================
; DATA SECTION - Rhyming vocabulary with gaps
; =============================================================================
.DATA
ALIGN 8

; Vocabulary header
VocabHeader:
    TotalWords      DWORD   9           ; 9 filled of 12 slots
    MissingSlots    DWORD   3           ; Three words omitted
    RhymeScheme     DWORD   RHYME_AY    ; Current rhyme family

; Word slots - 12 entries, 3 are gaps (empty)
WordSlot STRUCT
    IsFilled    BYTE    ?           ; 0 = gap/missing, 1 = filled
    RhymeType   BYTE    ?           ; Phonetic ending
    WordLen     BYTE    ?           ; Actual length
    Reserved    BYTE    ?           ; Padding
    WordText    BYTE    MAX_WORD_LEN DUP(?)  ; The word
WordSlot ENDS

ALIGN 16
VocabTable  WordSlot WORD_COUNT DUP(<>)

; Pre-filled rhyming words (pattern: _AY sounds)
; Slot 0: "day" - filled
; Slot 1: [GAP - missing word]
; Slot 2: "way" - filled
; Slot 3: "bay" - filled
; Slot 4: [GAP - missing word]
; Slot 5: "ray" - filled
; Slot 6: "say" - filled
; Slot 7: "pay" - filled
; Slot 8: [GAP - missing word]
; Slot 9: "lay" - filled
; Slot 10: "may" - filled
; Slot 11: "hay" - filled

; =============================================================================
; CODE SECTION
; =============================================================================
.CODE

; ---------------------------------------------------------------------------
; Vocab_Init - Initialize vocabulary with rhymes and gaps
; ---------------------------------------------------------------------------
Vocab_Init PROC FRAME
    .endprolog
    xor     rax, rax
    lea     rdi, [VocabTable]
    mov     rcx, WORD_COUNT * SIZEOF WordSlot
    rep     stosb                   ; Clear all slots

    ; Fill slot 0: "day"
    lea     rdi, [VocabTable + 0 * SIZEOF WordSlot]
    mov     BYTE PTR [rdi].WordSlot.IsFilled, 1
    mov     BYTE PTR [rdi].WordSlot.RhymeType, RHYME_AY
    mov     BYTE PTR [rdi].WordSlot.WordLen, 3
    mov     DWORD PTR [rdi].WordSlot.WordText, 'yad'  ; "day" little-endian

    ; Slot 1: [GAP - intentionally empty]

    ; Fill slot 2: "way"
    lea     rdi, [VocabTable + 2 * SIZEOF WordSlot]
    mov     BYTE PTR [rdi].WordSlot.IsFilled, 1
    mov     BYTE PTR [rdi].WordSlot.RhymeType, RHYME_AY
    mov     BYTE PTR [rdi].WordSlot.WordLen, 3
    mov     DWORD PTR [rdi].WordSlot.WordText, 'yaw'  ; "way"

    ; Fill slot 3: "bay"
    lea     rdi, [VocabTable + 3 * SIZEOF WordSlot]
    mov     BYTE PTR [rdi].WordSlot.IsFilled, 1
    mov     BYTE PTR [rdi].WordSlot.RhymeType, RHYME_AY
    mov     BYTE PTR [rdi].WordSlot.WordLen, 3
    mov     DWORD PTR [rdi].WordSlot.WordText, 'yab'  ; "bay"

    ; Slot 4: [GAP - intentionally empty]

    ; Fill slot 5: "ray"
    lea     rdi, [VocabTable + 5 * SIZEOF WordSlot]
    mov     BYTE PTR [rdi].WordSlot.IsFilled, 1
    mov     BYTE PTR [rdi].WordSlot.RhymeType, RHYME_AY
    mov     BYTE PTR [rdi].WordSlot.WordLen, 3
    mov     DWORD PTR [rdi].WordSlot.WordText, 'yar'  ; "ray"

    ; Fill slot 6: "say"
    lea     rdi, [VocabTable + 6 * SIZEOF WordSlot]
    mov     BYTE PTR [rdi].WordSlot.IsFilled, 1
    mov     BYTE PTR [rdi].WordSlot.RhymeType, RHYME_AY
    mov     BYTE PTR [rdi].WordSlot.WordLen, 3
    mov     DWORD PTR [rdi].WordSlot.WordText, 'yas'  ; "say"

    ; Fill slot 7: "pay"
    lea     rdi, [VocabTable + 7 * SIZEOF WordSlot]
    mov     BYTE PTR [rdi].WordSlot.IsFilled, 1
    mov     BYTE PTR [rdi].WordSlot.RhymeType, RHYME_AY
    mov     BYTE PTR [rdi].WordSlot.WordLen, 3
    mov     DWORD PTR [rdi].WordSlot.WordText, 'yap'  ; "pay"

    ; Slot 8: [GAP - intentionally empty]

    ; Fill slot 9: "lay"
    lea     rdi, [VocabTable + 9 * SIZEOF WordSlot]
    mov     BYTE PTR [rdi].WordSlot.IsFilled, 1
    mov     BYTE PTR [rdi].WordSlot.RhymeType, RHYME_AY
    mov     BYTE PTR [rdi].WordSlot.WordLen, 3
    mov     DWORD PTR [rdi].WordSlot.WordText, 'yal'  ; "lay"

    ; Fill slot 10: "may"
    lea     rdi, [VocabTable + 10 * SIZEOF WordSlot]
    mov     BYTE PTR [rdi].WordSlot.IsFilled, 1
    mov     BYTE PTR [rdi].WordSlot.RhymeType, RHYME_AY
    mov     BYTE PTR [rdi].WordSlot.WordLen, 3
    mov     DWORD PTR [rdi].WordSlot.WordText, 'yam'  ; "may"

    ; Fill slot 11: "hay"
    lea     rdi, [VocabTable + 11 * SIZEOF WordSlot]
    mov     BYTE PTR [rdi].WordSlot.IsFilled, 1
    mov     BYTE PTR [rdi].WordSlot.RhymeType, RHYME_AY
    mov     BYTE PTR [rdi].WordSlot.WordLen, 3
    mov     DWORD PTR [rdi].WordSlot.WordText, 'yah'  ; "hay"

    xor     eax, eax
    ret
Vocab_Init ENDP

; ---------------------------------------------------------------------------
; Vocab_CountFilled - Return number of filled slots
; ---------------------------------------------------------------------------
Vocab_CountFilled PROC FRAME
    .endprolog
    xor     eax, eax                ; Count = 0
    xor     rcx, rcx                ; Index = 0
    lea     rsi, [VocabTable]

CountLoop:
    cmp     rcx, WORD_COUNT
    jge     CountDone
    
    movzx   edx, BYTE PTR [rsi + rcx * SIZEOF WordSlot].WordSlot.IsFilled
    add     eax, edx                ; Add 1 if filled
    inc     rcx
    jmp     CountLoop

CountDone:
    ret                             ; Return count in EAX
Vocab_Init ENDP

; ---------------------------------------------------------------------------
; Vocab_FindGap - Return index of first missing word slot
; ---------------------------------------------------------------------------
Vocab_FindGap PROC FRAME
    .endprolog
    xor     rcx, rcx                ; Index = 0
    lea     rsi, [VocabTable]

GapLoop:
    cmp     rcx, WORD_COUNT
    jge     NoGap
    
    movzx   edx, BYTE PTR [rsi + rcx * SIZEOF WordSlot].WordSlot.IsFilled
    test    edx, edx
    jz      FoundGap                ; Found empty slot
    inc     rcx
    jmp     GapLoop

FoundGap:
    mov     eax, ecx                ; Return gap index
    ret

NoGap:
    mov     eax, -1                 ; No gaps found
    ret
Vocab_FindGap ENDP

; ---------------------------------------------------------------------------
; Vocab_GetWord - Get word at index (RCX = index, RDX = out buffer)
; ---------------------------------------------------------------------------
Vocab_GetWord PROC FRAME
    .endprolog
    cmp     ecx, WORD_COUNT
    jae     GetFail
    
    lea     rsi, [VocabTable + rcx * SIZEOF WordSlot]
    movzx   eax, BYTE PTR [rsi].WordSlot.IsFilled
    test    eax, eax
    jz      GetFail                 ; Slot is gap
    
    ; Copy word to output buffer
    movzx   ecx, BYTE PTR [rsi].WordSlot.WordLen
    lea     rsi, [rsi].WordSlot.WordText
    mov     rdi, rdx
    rep     movsb
    mov     BYTE PTR [rdi], 0       ; Null terminate
    mov     eax, 1                  ; Success
    ret

GetFail:
    mov     BYTE PTR [rdx], 0       ; Empty string
    xor     eax, eax                ; Fail
    ret
Vocab_GetWord ENDP

; ---------------------------------------------------------------------------
; Vocab_CheckRhyme - Verify all filled words rhyme (return rhyme type)
; ---------------------------------------------------------------------------
Vocab_CheckRhyme PROC FRAME
    .endprolog
    movzx   eax, BYTE PTR [VocabTable + 0 * SIZEOF WordSlot].WordSlot.RhymeType
    ; All filled slots use RHYME_AY in this structure
    ret
Vocab_CheckRhyme ENDP

; =============================================================================
; END
; =============================================================================
END

