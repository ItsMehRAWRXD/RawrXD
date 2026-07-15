; USG_minimal.asm - Minimal USG without rawrxd_win64.inc
; Metamorphic x64 engine for 21-bar musical code generation
; =============================================================================

OPTION CASEMAP:NONE
OPTION DOTNAME

; =============================================================================
; GENERATION MODES (bitflags)
; =============================================================================
MODE_PEACEFUL       EQU     00000001h   ; Peaceful tone
MODE_UNPEACEFUL     EQU     00000002h   ; Aggressive tone
MODE_CENSORED       EQU     00000004h   ; Filtered output
MODE_UNCENSORED     EQU     00000008h   ; Raw output
MODE_LYRICAL        EQU     00000010h   ; Rhyme structured
MODE_UNLYRICAL      EQU     00000020h   ; Freeform
MODE_DIGITAL        EQU     00000040h   ; Electronic aesthetic
MODE_ANALOG         EQU     00000080h   ; Organic aesthetic
MODE_UNDER_CLOUDS   EQU     00000100h   ; Subdued/subterranean
MODE_ABOVE_CLOUDS   EQU     00000200h   ; Elevated/ethereal
MODE_RAP            EQU     00000400h   ; Rhythmic cadence
MODE_NON_BLAP       EQU     00000800h   ; Irregular cadence
MODE_METAMORPHIC    EQU     80000000h   ; Self-modifying

; Bar structure
BARS_TOTAL          EQU     21
BARS_UNBARRED       EQU     11          ; Open/free bars
BARS_BARRED         EQU     10          ; Structured bars
MAX_STUB_SIZE       EQU     4096

; =============================================================================
; DATA SECTION
; =============================================================================
.DATA
ALIGN 16

; Generation state
USG_State STRUCT
    ModeFlags       DWORD   ?           ; Current mode
    CurrentBar      BYTE    ?           ; 0-20
    IsBarred        BYTE    ?           ; 0=unbarred, 1=barred
    MorphSeed       DWORD   ?           ; PRNG seed
    OutputPtr       QWORD   ?           ; Current write position
    OutputEnd       QWORD   ?           ; Buffer end
USG_State ENDS

ALIGN 16
State       USG_State   <>

; Instruction mutation table (metamorphic substitutions)
ALIGN 16
MutTable:
    DB  090h, 090h, 090h, 090h
    DB  048h, 089h, 0C0h, 048h
    DB  048h, 031h, 0C0h, 048h
    DB  048h, 001h, 0C0h, 048h
    DB  048h, 0FFh, 0C0h, 048h
    DB  048h, 0FFh, 0C8h, 048h
    DB  0EBh, 000h, 090h, 090h
    DB  074h, 000h, 00Fh, 084h
    DB  075h, 000h, 00Fh, 085h
    DB  0C3h, 0C2h, 000h, 000h

; Bar templates (21 entries, each 64 bytes)
ALIGN 16
BarTemplates:
    DB  "USG_INIT", 0, 0, 0, 0, 0, 0, 0
    DB  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
    DB  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
    DB  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
    DB  "BAR_START", 0, 0, 0, 0, 0, 0
    DB  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
    DB  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
    DB  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
    DB  64 * 19 DUP(0)

; Output buffer
ALIGN 16
OutputBuffer    DB  MAX_STUB_SIZE DUP(0)

; =============================================================================
; CODE SECTION
; =============================================================================
.CODE

; ---------------------------------------------------------------------------
; USG_Init - Initialize generator with mode flags
; RCX = ModeFlags
; ---------------------------------------------------------------------------
USG_Init PROC FRAME
    .endprolog
    mov     [State.ModeFlags], ecx
    mov     BYTE PTR [State.CurrentBar], 0
    mov     BYTE PTR [State.IsBarred], 0
    mov     DWORD PTR [State.MorphSeed], 0DEADBEEFh
    lea     rax, [OutputBuffer]
    mov     [State.OutputPtr], rax
    lea     rax, [OutputBuffer + MAX_STUB_SIZE]
    mov     [State.OutputEnd], rax
    xor     eax, eax
    ret
USG_Init ENDP

; ---------------------------------------------------------------------------
; USG_PRNG - Simple LCG for metamorphic decisions
; Returns: EAX = random value
; ---------------------------------------------------------------------------
USG_PRNG PROC FRAME
    .endprolog
    mov     eax, [State.MorphSeed]
    imul    eax, eax, 1103515245
    add     eax, 12345
    mov     [State.MorphSeed], eax
    ret
USG_PRNG ENDP

; ---------------------------------------------------------------------------
; USG_SelectMorph - Choose metamorphic variant
; RCX = instruction index
; Returns: RAX = pointer to variant bytes
; ---------------------------------------------------------------------------
USG_SelectMorph PROC FRAME
    .endprolog
    push    rcx
    call    USG_PRNG
    pop     rcx
    and     eax, 3
    shl     ecx, 2
    lea     rdx, [MutTable]
    add     edx, ecx
    movzx   eax, BYTE PTR [rdx + rax]
    ret
USG_SelectMorph ENDP

; ---------------------------------------------------------------------------
; USG_WriteByte - Write single byte to output
; CL = byte to write
; ---------------------------------------------------------------------------
USG_WriteByte PROC FRAME
    .endprolog
    mov     rax, [State.OutputPtr]
    cmp     rax, [State.OutputEnd]
    jae     WriteFull
    mov     BYTE PTR [rax], cl
    inc     QWORD PTR [State.OutputPtr]
    mov     al, 1
    ret
WriteFull:
    xor     al, al
    ret
USG_WriteByte ENDP

; ---------------------------------------------------------------------------
; USG_GenerateBar - Generate single bar
; RCX = bar index (0-20)
; ---------------------------------------------------------------------------
USG_GenerateBar PROC FRAME
    push    rbp
    .pushreg rbp
    push    rbx
    .pushreg rbx
    push    rsi
    .pushreg rsi
    push    rdi
    .pushreg rdi
    mov     rbp, rsp
    .setframe rbp, 0
    sub     rsp, 32
    .allocstack 32
    .endprolog

    mov     ebx, ecx
    cmp     ebx, BARS_UNBARRED
    jb      UnbarredBar
    mov     BYTE PTR [State.IsBarred], 1
    jmp     GenerateContent
UnbarredBar:
    mov     BYTE PTR [State.IsBarred], 0

GenerateContent:
    mov     eax, [State.ModeFlags]
    test    eax, MODE_METAMORPHIC
    jz      StandardGen
    mov     ecx, ebx
    and     ecx, 7
    call    USG_SelectMorph
    mov     cl, al
    call    USG_WriteByte
    jmp     BarDone

StandardGen:
    test    eax, MODE_PEACEFUL
    jnz     GenPeaceful
    test    eax, MODE_UNPEACEFUL
    jnz     GenUnpeaceful
    test    eax, MODE_DIGITAL
    jnz     GenDigital
    mov     cl, 090h
    call    USG_WriteByte

BarDone:
    mov     rsp, rbp
    pop     rdi
    pop     rsi
    pop     rbx
    pop     rbp
    ret

GenPeaceful:
    mov     cl, 048h
    call    USG_WriteByte
    mov     cl, 031h
    call    USG_WriteByte
    mov     cl, 0C0h
    call    USG_WriteByte
    jmp     BarDone

GenUnpeaceful:
    mov     cl, 048h
    call    USG_WriteByte
    mov     cl, 0FFh
    call    USG_WriteByte
    mov     cl, 0C0h
    call    USG_WriteByte
    jmp     BarDone

GenDigital:
    mov     cl, 00Fh
    call    USG_WriteByte
    mov     cl, 038h
    call    USG_WriteByte
    jmp     BarDone

USG_GenerateBar ENDP

; ---------------------------------------------------------------------------
; USG_Generate21 - Generate all 21 bars
; Returns: RAX = pointer to generated stub
;          RCX = size in bytes
; ---------------------------------------------------------------------------
USG_Generate21 PROC FRAME
    push    rbp
    .pushreg rbp
    push    rbx
    .pushreg rbx
    mov     rbp, rsp
    .setframe rbp, 0
    sub     rsp, 32
    .allocstack 32
    .endprolog

    xor     ebx, ebx

BarLoop:
    cmp     bl, BARS_TOTAL
    jae     GenerationDone
    mov     ecx, ebx
    call    USG_GenerateBar
    inc     bl
    jmp     BarLoop

GenerationDone:
    mov     rax, [State.OutputPtr]
    lea     rdx, [OutputBuffer]
    sub     rax, rdx
    lea     rax, [OutputBuffer]
    mov     rcx, [State.OutputPtr]
    sub     rcx, rax
    mov     rsp, rbp
    pop     rbx
    pop     rbp
    ret
USG_Generate21 ENDP

; ---------------------------------------------------------------------------
; USG_SelfModify - Metamorphic engine entry
; ---------------------------------------------------------------------------
USG_SelfModify PROC FRAME
    .endprolog
    call    USG_PRNG
    and     eax, 0FFh
    mov     ecx, eax
    call    USG_SelectMorph
    mov     cl, al
    call    USG_WriteByte
    ret
USG_SelfModify ENDP

; ---------------------------------------------------------------------------
; USG_ModeSwitch - Switch between modes dynamically
; RCX = new mode flags
; ---------------------------------------------------------------------------
USG_ModeSwitch PROC FRAME
    .endprolog
    mov     [State.ModeFlags], ecx
    test    ecx, MODE_METAMORPHIC
    jz      NoMorph
    call    USG_SelfModify
NoMorph:
    xor     eax, eax
    ret
USG_ModeSwitch ENDP

; =============================================================================
; ENTRY POINT - Standalone test
; =============================================================================
USG_Entry PROC FRAME
    push    rbp
    .pushreg rbp
    mov     rbp, rsp
    .setframe rbp, 0
    sub     rsp, 32
    .allocstack 32
    .endprolog

    mov     ecx, 00000041h
    call    USG_Init
    call    USG_Generate21

    xor     ecx, ecx
    call    ExitProcess

USG_Entry ENDP

; =============================================================================
; EXPORTS
; =============================================================================
PUBLIC USG_Init
PUBLIC USG_Generate21
PUBLIC USG_ModeSwitch
PUBLIC USG_SelfModify
PUBLIC USG_Entry

EXTERN ExitProcess:PROC

; =============================================================================
; END
; =============================================================================
END

